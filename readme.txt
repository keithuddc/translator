pyinstaller --onefile --add-data "version.json;." --windowed --name="翻译工具" --icon=icon.ico translator.py

1.开通服务
打开 https://console.cloud.tencent.com/tmt
开通机器翻译服务
2.申请api
打开https://console.cloud.tencent.com/cam/capi
点击新建密钥生成 secretId和 secretKey
3.打开exe点击左上角配置
把第2步生成的secretId和 secretKey 填入
填写翻译的语言和对应追加文件的映射关系
最后生成config.json
例如：
{
    "secret_id": "xxx",
    "secret_key": "xxx",
    "file_mapping": {
        "en": "messaging_en_US.properties",
        "es": "messaging_es_ES.properties",
        "ar": "messaging_ar_SA.properties",
        "th": "messaging_th_TH.properties",
        "pt": "messaging_pt_PT.properties",
        "fr": "messaging_fr_FR.properties",
        "zh": "zh.json",
        "zh-TW": "messaging_zh_TW.properties"
    }
}
