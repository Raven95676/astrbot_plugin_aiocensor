# astrbot_plugin_aiocensor

> [!important]
> 本项目处于Beta阶段，仅保证审核功能正常工作。WebUI大部分功能未完成。 
>
> 本项目依赖aiosqlite实现异步数据库操作，依赖kwmatcher进行本地关键词匹配。理论上这些依赖会自动安装。
>
> 所有新功能Issue以及WebUI相关问题将推迟至9月份完成，此前仅会修复审核功能的问题。

Astrbot 综合内容安全+群管插件。

自动处置功能使用了[astrbot_plugin_anti_porn](https://github.com/zouyonghe/astrbot_plugin_anti_porn)的源码。

## 兼容的适配器

已测试：
- aiocqhttp
- telegram

完全兼容（功能包括自动处置）：
- aiocqhttp

部分兼容（功能不包括自动处置）：
- telegram

理论部分兼容：
- gewechat
- lark

## 特点

### 灵活的本地关键词规则

使用&表示要求多个关键词同时出现，使用~表示排除包含特定关键词。排除条件组内部可用&连接，要求组内的所有关键词必须同时存在。

假设有如下关键词规则：

`A&B~C&D&E~F&G&H&I&J`

将被解析为两个组：

包含组：

{"A","B"}
排除组：

{"C","D","E"}
{"F","G","H","I","J"}
如果文本缺少"A"或"B"中的任意一个，匹配失败。

如果文本同时包含"C"、"D"、"E"全部三个，匹配失败。

如果文本同时包含"F"、"G"、"H"、"I"、"J" 全部五个，匹配失败。

在包含组都出现的情况下，只要任一排除组全部出现就匹配失败。

### 多提供商支持

除去本地审核外，还支持：

- 阿里云内容安全（文本、图片链接）
- 腾讯内容安全（文本、图片链接、图片base64）
- 基于OpenAI兼容的LLM审核（文本、图片链接、图片base64）
