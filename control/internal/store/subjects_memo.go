package store

import (
	"context"
	"sync"
)

// 请求作用域的 SubjectIndex 备忘（wave9）。
//
// ★这不是那个被明令禁止的缓存。SubjectIndex 的注释写着「每次调用都现算、不缓存，
// 这是一条安全属性」——指的是**跨请求**不缓存：把人移出组织后，下一次网关轮询
// 就该连不上。本备忘的生命周期严格是**一次请求**，且必须由调用方显式开启
// （WithSubjectIndexMemo），默认行为一字未改。
//
// 修的是一次请求内算两遍的浪费，而它同时是个正确性问题：客户端剖面这一条路上，
// store 层的 fillAppAuth 与 api 层的 buildProfile 各算一次，中间若有目录写入，
// 「这个应用可不可达」与「有没有这条路由」就会基于两份不同的展开——
// 同一份剖面里自相矛盾，而两处都不报错。
type subjectMemoKey struct{}

type subjectMemo struct {
	mu   sync.Mutex
	done bool
	ix   SubjectIndex
	err  error
}

// WithSubjectIndexMemo 给 ctx 挂一个请求作用域的展开索引备忘。
// 同一个 ctx 下的多次 SubjectIndex 调用只真算一次（错误同样只发生一次并被复用）。
// 不调用它 = 行为与改造前逐字相同。
func WithSubjectIndexMemo(ctx context.Context) context.Context {
	if ctx.Value(subjectMemoKey{}) != nil {
		return ctx // 已挂过，别套第二层（否则内层那次仍会各算各的）
	}
	return context.WithValue(ctx, subjectMemoKey{}, &subjectMemo{})
}

// memoizedSubjectIndex 若 ctx 上挂了备忘则走它，否则直接现算。
func memoizedSubjectIndex(ctx context.Context, compute func(context.Context) (SubjectIndex, error)) (SubjectIndex, error) {
	m, _ := ctx.Value(subjectMemoKey{}).(*subjectMemo)
	if m == nil {
		return compute(ctx)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.done {
		m.ix, m.err = compute(ctx)
		m.done = true
	}
	return m.ix, m.err
}
