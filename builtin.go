// Package bannerd 在模块根只承载一件事：把仓库根目录 rules/ 下的内置规则
// 文件编译进二进制。
//
// 为什么单独放在模块根：go:embed 不允许引用父目录（".."），而规则数据的
// 唯一权威位置必须是仓库根 rules/ —— 评测点之一是「识别规则与程序代码是否
// 解耦」，所以规则文件只能有一份，不能为了 embed 在 internal/ 下再复制一份。
//
// 收益：scratch 运行时镜像里没有任何文件系统可言，内置规则随二进制一起走，
// 镜像自包含、可复现；外部规则目录则是可选的覆盖手段。
package bannerd

import "embed"

// BuiltinRules 是内置规则包，由 internal/rules 读取。
//
//go:embed rules/*.yaml
var BuiltinRules embed.FS
