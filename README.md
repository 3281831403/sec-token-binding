访问令牌加了绑定证明，抓包重放请求仍然成功，换个客户端也照样能用：请求指纹计算漏掉方法，换用其他方法仍可复用同一证明；URL 未统一大小写并排序查询参数，等价请求得到不同指纹；请求主体只取长度而不取摘要，长度相同的不同主体发生碰撞；证明串使用逗号拼接且不转义字段，字段内逗号可转移内容；证明串没有包含 key_id，轮换密钥后旧证明仍然可以通过；证明签名比较使用普通等号，不是恒定时间比较；nonce 只写入记录从不删除，同一个 nonce 第二次校验仍通过；nonce 存储不清理过期项，nonce 的有效窗口被无限延长；时间窗只拒绝过旧时间戳，不拒绝过新的时间戳；批量校验复用第一个请求的指纹，后续请求沿用错误指纹。engine/proof/binding.py 是核心，tests/proof/test_binding.py 15个红。要修的是：按上面的顺序把 10 个缺陷逐个修掉。

令牌绑定证明
============

字段表
------

领域        安全
题型        漏洞检测与攻防
任务类型    Bugfix
技术栈      Python 3, pytest
外部依赖    无外部依赖

运行方式
--------

在仓库根目录执行：

    python -m pytest tests -q

当前基线应为恰好 15 failed，且不得出现 error。修复目标是在不修改 tests 的前提下让 15 个用例全部通过。

题目约束
--------

tests 目录不可修改，测试就是验收标准。engine/proof/binding.py 是唯一实现文件，恰好包含 8 个函数桩，修复时保持这 8 个公开函数的名字、参数顺序与返回类型不变。

目录布局
--------

sec-token-binding/
  README.md
  conftest.py
  engine/
    __init__.py
    proof/
      __init__.py
      binding.py
  tests/
    proof/
      test_binding.py

这是 engine 嵌套布局：实现位于 engine/proof/binding.py，测试位于 tests/proof/test_binding.py。仓库根的 conftest.py 把仓库根加入 sys.path，因此测试可以直接导入 engine.proof.binding，不需要安装包，也不需要外部依赖。

8 个函数桩
----------

request_fingerprint(method, url, body)
proof_payload(fingerprint, nonce, issued_at, key_id)
make_proof(key, payload)
verify_proof(key, payload, proof)
nonce_check(store, nonce, now, ttl)
clock_ok(issued_at, now, window)
check_binding(token, proof, request)
binding_batch(requests, policy, now)

核心约定
--------

token 至少包含 key 和 key_id。request 至少包含 method、url、body、nonce、issued_at、key_id、now、window、nonce_ttl、nonce_store。proof 是 make_proof 的十六进制字符串。check_binding 返回 fingerprint、proof_ok、key_id_ok、clock_ok、nonce_ok、valid。binding_batch 的 policy 至少包含 window、nonce_ttl、nonce_store，结果按请求 id 返回与 check_binding 同形的字典。

缺陷分布
--------

10 个缺陷集中在证明值计算覆盖范围、nonce 一次性、时钟窗、密钥绑定和请求指纹五个方面，并跨 request_fingerprint、proof_payload、make_proof、verify_proof、nonce_check、clock_ok、check_binding、binding_batch 保持一致。修复必须同时考虑算法语义、边界条件和批量场景下的独立性，不能只针对单个断言打补丁。

## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |

