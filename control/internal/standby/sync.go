package standby

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"baidi.dev/control/internal/upgrade"
)

// 备机侧：校验 + 落盘。
//
// ★这一段的唯一职责是让「盘上那份一定是能用的」。备机拿到的字节流可能是
// 半截响应、也可能是主机换了口令之后的另一份——**校验不过就绝不覆盖本地已有的那份**：
// 覆盖了的话，切换那天才会发现手上这份解不开，而此前每一天页面都显示"同步正常"。

const (
	// BackupFile 盘上那份已校验通过的加密备份。
	BackupFile = "latest.bak"
	// StateFile 同步状态（明文 JSON，不含任何凭据）。
	//
	// ★它只是给人和脚本看的状态，**不是信任根**：提升流程的权威判据是 latest.bak
	// 自身（明文头 + AES-GCM 认证），promote-standby.sh 会重新校验一遍而不是读这里。
	StateFile = "latest.json"
)

// ErrIncomplete 备份内容不完整（解得开，但缺关键材料）。
var ErrIncomplete = errors.New("备份内容不完整")

// LocalState 备机盘上那份的状态。
type LocalState struct {
	NodeID string `json:"nodeId"`
	// SyncedAt 备机本地落盘时间（展示用）。**主机侧的新鲜度不用它**——
	// 那边按收到回报的服务端时间算，客户端时钟不参与任何判定。
	SyncedAt        string   `json:"syncedAt"`
	SHA256          string   `json:"sha256"`
	Bytes           int      `json:"bytes"`
	BackupVersion   string   `json:"backupVersion"`
	BackupCreatedAt string   `json:"backupCreatedAt"`
	Files           []string `json:"files"`
	IntervalSec     int      `json:"intervalSec"`
	Primary         string   `json:"primary"`
}

// VerifyBackup 校验一份备份：解密（AES-GCM 认证即完整性校验）+ 必须含数据库。
//
// 返回明文头与归档内文件清单。**只验头部是不够的**：头部是明文，
// 一个把头部原样保留、密文改了一个字节的文件也能通过头部检查。
func VerifyBackup(blob []byte, passphrase string) (upgrade.BackupMeta, []string, error) {
	meta, files, err := upgrade.OpenBackup(blob, passphrase)
	if err != nil {
		return meta, nil, err
	}
	if _, ok := files["baidi.db"]; !ok {
		// 没有数据库的备份恢复出来是一套空系统：用户、策略、审计全没了，
		// 而服务能正常起来——这是最坏的一种"恢复成功"。
		return meta, nil, fmt.Errorf("%w：归档里没有 baidi.db", ErrIncomplete)
	}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	return meta, names, nil
}

// Adopt 校验一份新拉到的备份并原子落盘；校验不过时**不动本地任何文件**。
func Adopt(dir string, blob []byte, passphrase, nodeID, primary string, intervalSec int, now time.Time) (LocalState, error) {
	meta, files, err := VerifyBackup(blob, passphrase)
	if err != nil {
		return LocalState{}, err
	}
	sum := sha256.Sum256(blob)
	st := LocalState{
		NodeID: nodeID, SyncedAt: now.Format("2006-01-02 15:04:05"),
		SHA256: hex.EncodeToString(sum[:]), Bytes: len(blob),
		BackupVersion: meta.Version, BackupCreatedAt: meta.CreatedAt,
		Files: sortedFiles(files, meta), IntervalSec: intervalSec, Primary: primary,
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return LocalState{}, err
	}
	// 备份里装着 CA 私钥与全部凭据（虽已加密），0600 是底线。
	if err := writeAtomic(filepath.Join(dir, BackupFile), blob, 0o600); err != nil {
		return LocalState{}, err
	}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return LocalState{}, err
	}
	// 状态文件排在备份之后落：中途失败的结果是「备份已是新的、状态文件还是旧的」，
	// 而提升流程本来就重新校验备份本身，不吃这个文件。反过来（先写状态）则会出现
	// 「状态说有一份新的、盘上还是旧的」——那正是切换时最不该有的误导。
	return st, writeAtomic(filepath.Join(dir, StateFile), b, 0o600)
}

// LoadLocal 读盘上那份状态；ok=false 表示从未成功同步过。
func LoadLocal(dir string) (LocalState, bool, error) {
	b, err := os.ReadFile(filepath.Join(dir, StateFile))
	if errors.Is(err, os.ErrNotExist) {
		return LocalState{}, false, nil
	}
	if err != nil {
		return LocalState{}, false, err
	}
	var st LocalState
	if err := json.Unmarshal(b, &st); err != nil {
		return LocalState{}, false, err
	}
	return st, true, nil
}

// writeAtomic 同目录临时文件 + rename。
// 直接覆写的话，进程在写一半时被杀就会留下一份长度对、内容截断的备份——
// 而截断的备份在头部检查这一层看起来完全正常。
func writeAtomic(path string, body []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(body); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// sortedFiles 归档内文件清单：优先用备份头里登记的顺序（可读），缺失时回落实际解出的名字。
func sortedFiles(actual []string, meta upgrade.BackupMeta) []string {
	if len(meta.Files) > 0 {
		return meta.Files
	}
	return actual
}

// ExtractTo 把一份已校验的备份解到目录（提升流程用；不做任何目标路径推导）。
//
// ★路径穿越已在 upgrade.OpenBackup 的解包里挡住（`..` / 绝对路径一律拒），
// 这里只负责按归档内的相对名建目录写文件，并**原样保留权限位**——
// CA 私钥恢复成 0644 等于把私钥暴露给同机其他用户，而系统照常运行、没有任何报错。
// 权限位没有随归档回传（tar 头有，但 OpenBackup 只回内容），故按名字判：
// 密钥类一律 0600，其余 0644。
func ExtractTo(outDir string, blob []byte, passphrase string) ([]string, error) {
	_, files, err := upgrade.OpenBackup(blob, passphrase)
	if err != nil {
		return nil, err
	}
	if _, ok := files["baidi.db"]; !ok {
		return nil, fmt.Errorf("%w：归档里没有 baidi.db", ErrIncomplete)
	}
	names := make([]string, 0, len(files))
	for name, body := range files {
		dst := filepath.Join(outDir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return nil, err
		}
		if err := os.WriteFile(dst, body, permFor(name)); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	return names, nil
}

// permFor 按名字判权限位：只有 .pub（公钥，本来就该公开）是 0644，其余一律 0600。
// 默认收紧而不是默认放开——归档里混着 CA 私钥、JWT 私钥、审计链密钥和整个数据库，
// 判错一次的代价是同机任何用户都能读走整套信任材料，而系统照常运行、无任何报错。
func permFor(name string) os.FileMode {
	if filepath.Ext(name) == ".pub" {
		return 0o644
	}
	return 0o600
}
