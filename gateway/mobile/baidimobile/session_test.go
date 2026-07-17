package baidimobile

import (
	"errors"
	"testing"

	"baidi.dev/gateway/internal/knock"
)

// 引擎运行中：Running 为真、Reason 为空。
func TestSessionRunningInitially(t *testing.T) {
	s := &Session{}
	if !s.Running() {
		t.Fatal("新建 Session 应处于运行态")
	}
	if s.Reason() != "" {
		t.Fatalf("运行中 Reason 应为空，得到 %q", s.Reason())
	}
}

// 定性拒绝退出：Running 变假、Reason 带出原因，供移动端 UI 轮询显示。
func TestSessionMarkStoppedDeny(t *testing.T) {
	s := &Session{}
	s.markStopped(errors.Join(knock.ErrDenied, errors.New("账号已被禁用，无法接入")))
	if s.Running() {
		t.Fatal("被拒后应停机")
	}
	if r := s.Reason(); r == "" {
		t.Fatal("被拒后 Reason 应非空")
	}
}

// 正常关闭（dev 关闭，err 为 nil）：停机但 Reason 空（非异常）。
func TestSessionMarkStoppedNormal(t *testing.T) {
	s := &Session{}
	s.markStopped(nil)
	if s.Running() {
		t.Fatal("关闭后应停机")
	}
	if s.Reason() != "" {
		t.Fatalf("正常关闭 Reason 应为空，得到 %q", s.Reason())
	}
}
