# 保全库

管理内容寻址对象、案件、保全清单、流转与保留规则。对象可能被多个案件、封存记录、临时 pin 或副本策略共同引用。

演练使用本地合成对象完成入库、封存与流转核验。哈希和本地见证不等于外部签名；逻辑删除不承诺物理安全擦除。

主要代码位于 sealvault，按 custody、retention、transfer、inspect 划分职责；tests 保存领域行为、边界及存储回归用例。命令接收严格 JSON，详细操作名与字段可通过对应帮助入口及 service 中的注册表查询。示例中的机构、客户、案件和测量均为本地合成记录，不涉及真实个人资料。

使用 Python 3.11.2 与标准库，无第三方包。运行无需访问外部服务或提供账号。依赖清单 requirements.txt 为空，.python-version 固定解释器版本。

在项目根目录运行：

```sh
python3 -m unittest discover -s tests -v
python3 -m compileall -q sealvault
python3 -m sealvault replay fixtures/sealing.json
```

也可执行下面的统一检查，按顺序进行语法编译、领域回归和完整本地演练，任一环节失败即退出。运行写入均在临时目录或内存数据库，重复执行不需清理已有业务账。正常数据规模的检查可在 90 秒内完成。

```sh
sh scripts/check.sh
```
