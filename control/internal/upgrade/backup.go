package upgrade

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// 配置备份与恢复（PRD FR-UPG-09/10，同时补上第 15.8 章的 P0 缺口）。
//
// ★为什么必须加密：备份里装着这台机器上**全部**的信任材料——CA 私钥、
// 网关证书、IPSec PSK、认证源凭据、审计链 HMAC 密钥、JWT 签名私钥。
// 一份明文备份被拿走，等于整套系统被接管，而且没有任何日志会显示这件事发生过。
// 所以：口令派生密钥（PBKDF2-SHA256）+ AES-256-GCM，且**不提供不加密的导出选项**。
//
// ★为什么不做「自动上传到某处」：备份该放哪里是管理员的决定，
// 替他决定意味着把全部信任材料推到一个他没审过的地方。

const (
	backupMagic   = "BAIDI-BACKUP-V1"
	pbkdf2Iters   = 600_000 // OWASP 2023 对 PBKDF2-HMAC-SHA256 的建议下限
	saltLen       = 16
	minPassphrase = 12
)

var (
	ErrBackupPassphrase = errors.New("备份口令过短")
	ErrBackupFormat     = errors.New("备份文件格式不正确")
	ErrBackupDecrypt    = errors.New("备份解密失败（口令错误或文件已损坏）")
)

// BackupMeta 备份的明文头部：**刻意不加密**，好让管理员在不解密的前提下
// 看清「这份备份是哪台机器、哪个版本、什么时候做的」。
// 里面绝不放任何凭据——头部是明文的，放什么都等于公开。
type BackupMeta struct {
	Magic     string   `json:"magic"`
	Version   string   `json:"version"`   // 备份时的控制面版本（恢复时比对，防跨版本乱恢复）
	CreatedAt string   `json:"createdAt"` // 由调用方注入，避免包内取时间不可测
	Note      string   `json:"note,omitempty"`
	Files     []string `json:"files"` // 归档内相对路径清单（便于恢复前预览）
}

// BackupSource 一份要备份的材料。
type BackupSource struct {
	// Name 归档内的相对路径，如 "baidi.db"、"pki/ca.key"。
	Name string
	Path string // 磁盘绝对路径
}

// CreateBackup 把 sources 打成 tar.gz 后整体加密写入 w。
//
// 布局：明文 JSON 头（一行）+ '\n' + salt(16) + nonce(12) + AES-256-GCM 密文。
// 头部与密文用 GCM 的 AAD 绑定——不绑的话，攻击者可以把 A 机器的头部拼到
// B 机器的密文上，让管理员以为自己在恢复 A 的配置。
func CreateBackup(w io.Writer, meta BackupMeta, passphrase string, sources []BackupSource) error {
	if len([]rune(passphrase)) < minPassphrase {
		return fmt.Errorf("%w: 至少 %d 个字符（备份里装着 CA 私钥与全部凭据）", ErrBackupPassphrase, minPassphrase)
	}
	meta.Magic = backupMagic
	meta.Files = nil
	for _, s := range sources {
		meta.Files = append(meta.Files, s.Name)
	}
	head, err := json.Marshal(meta)
	if err != nil {
		return err
	}

	buf, err := tarGz(sources)
	if err != nil {
		return err
	}

	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	gcm, err := gcmFrom(passphrase, salt)
	if err != nil {
		return err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	sealed := gcm.Seal(nil, nonce, buf, head) // head 作为 AAD

	if _, err := w.Write(append(head, '\n')); err != nil {
		return err
	}
	if _, err := w.Write(salt); err != nil {
		return err
	}
	if _, err := w.Write(nonce); err != nil {
		return err
	}
	_, err = w.Write(sealed)
	return err
}

// ReadBackupMeta 只读明文头部，不解密——恢复前的预览用。
func ReadBackupMeta(b []byte) (BackupMeta, []byte, error) {
	i := bytes.IndexByte(b, '\n')
	if i < 0 {
		return BackupMeta{}, nil, fmt.Errorf("%w: 找不到头部", ErrBackupFormat)
	}
	var m BackupMeta
	if err := json.Unmarshal(b[:i], &m); err != nil {
		return BackupMeta{}, nil, fmt.Errorf("%w: 头部不是合法 JSON", ErrBackupFormat)
	}
	if m.Magic != backupMagic {
		return BackupMeta{}, nil, fmt.Errorf("%w: 不是白帝备份文件（magic=%q）", ErrBackupFormat, m.Magic)
	}
	return m, b[i+1:], nil
}

// OpenBackup 校验头部并解密，返回归档内的文件内容。
func OpenBackup(b []byte, passphrase string) (BackupMeta, map[string][]byte, error) {
	meta, rest, err := ReadBackupMeta(b)
	if err != nil {
		return meta, nil, err
	}
	head := b[:len(b)-len(rest)-1]
	if len(rest) < saltLen+12 {
		return meta, nil, fmt.Errorf("%w: 密文长度不足", ErrBackupFormat)
	}
	salt, rest := rest[:saltLen], rest[saltLen:]
	gcm, err := gcmFrom(passphrase, salt)
	if err != nil {
		return meta, nil, err
	}
	ns := gcm.NonceSize()
	nonce, ct := rest[:ns], rest[ns:]
	plain, err := gcm.Open(nil, nonce, ct, head)
	if err != nil {
		// 不区分「口令错」与「文件损坏」：GCM 认证失败时两者本就无法区分，
		// 分开报会变成一个口令探测口。
		return meta, nil, ErrBackupDecrypt
	}
	files, err := unTarGz(plain)
	return meta, files, err
}

func gcmFrom(passphrase string, salt []byte) (cipher.AEAD, error) {
	key := pbkdf2.Key([]byte(passphrase), salt, pbkdf2Iters, 32, sha256.New)
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

func tarGz(sources []BackupSource) ([]byte, error) {
	var out bytes.Buffer
	gz := gzip.NewWriter(&out)
	tw := tar.NewWriter(gz)
	for _, s := range sources {
		fi, err := os.Stat(s.Path)
		if err != nil {
			if os.IsNotExist(err) {
				continue // 可选材料（如未启用的国密证书目录）缺席是正常的
			}
			return nil, err
		}
		if fi.IsDir() {
			if err := addDir(tw, s); err != nil {
				return nil, err
			}
			continue
		}
		if err := addFile(tw, s.Name, s.Path, fi); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func addDir(tw *tar.Writer, s BackupSource) error {
	return filepath.WalkDir(s.Path, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(s.Path, p)
		if err != nil {
			return err
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		return addFile(tw, filepath.ToSlash(filepath.Join(s.Name, rel)), p, fi)
	})
}

func addFile(tw *tar.Writer, name, path string, fi os.FileInfo) error {
	body, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	// 权限位必须原样保留：CA 私钥是 0600，恢复成 0644 等于把私钥暴露给同机其他用户，
	// 而系统照常运行、没有任何报错。
	if err := tw.WriteHeader(&tar.Header{
		Name: name, Mode: int64(fi.Mode().Perm()), Size: int64(len(body)), Typeflag: tar.TypeReg,
	}); err != nil {
		return err
	}
	_, err = tw.Write(body)
	return err
}

func unTarGz(b []byte) (map[string][]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBackupFormat, err)
	}
	defer gz.Close() //nolint:errcheck
	tr := tar.NewReader(gz)
	out := map[string][]byte{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrBackupFormat, err)
		}
		// 路径穿越防护：备份文件可能来自任何地方，一条 ../../etc/xxx 就能在恢复时
		// 覆写系统文件。恢复方按名字写盘，所以必须在这里就把它挡住。
		if strings.Contains(h.Name, "..") || strings.HasPrefix(h.Name, "/") {
			return nil, fmt.Errorf("%w: 归档内含非法路径 %q", ErrBackupFormat, h.Name)
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			return nil, err
		}
		out[h.Name] = body
	}
}
