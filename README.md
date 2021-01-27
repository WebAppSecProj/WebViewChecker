# WebViewChecker 

## Introduction
The **WebViewChecker** is used to distill argument of webview component.

```shell
usage: WebViewCheckerCHA [-h] -f FILE

Distill argument of WebView.

named arguments:
-h, --help             show this help message and exit
-f FILE, --file FILE   APK file to check
```

Currently, it can parse argument of such models:

1. testcase/435738b93f9baed84b62400996ef07a3.apk
```java
this.webView.loadUrl(getString(R.string.url));
```

2. testcase/a3ec5b6abe04471d3311a157ed1ae852.apk
```java
this.wv.loadUrl(Config.okurl);
```

# How it works
The code snippet from testcase/435738b93f9baed84b62400996ef07a3.apk depicts that 
```java
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        makeStatusBarTransparent(this);
1->     this.webView = (WebView) findViewById(R.id.webview);
        this.llError = (LinearLayout) findViewById(R.id.llError);
        initWeb();
        registerForContextMenu(this.webView);
2->     this.webView.loadUrl(getString(R.string.url));
    }
```
the `webView` of line 2 comes from line 1. 
Since there is no abstract for `findViewById` in line 1, 
`Spark` fails to solve the `loadUrl` in line 2 (check WebViewAnalyzerSpark.java). 
So I give up using `Spark` but to build the analysis from the scratch. 

