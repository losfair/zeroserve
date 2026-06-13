win-c
============

C/C++から使えるWindowsのコンソールアプリケーション用のライブラリです。

__関数__

* `getopt() / getopt_long()` - コマンドラインオプション解析

## `getopt() / getopt_long()` - コマンドラインオプション解析

関数の仕様は、[POSIXのgetopt](http://linuxjm.sourceforge.jp/html/LDP_man-pages/man3/getopt.3.html)を参照してください。

* 長いオプションの`optional_argument` と `getopt_long_only()`は、対応していません。

### 使用例

以下は、C++での使い方サンプルです。

```
#include <iostream>
#include "getopt.h"
using namespace std;
int main(int argc, char* argv[]) {
    //オプションの定義。a, b, c, dで、bとcは引数を取る
    //  -a
    //  -b <opt_b_arg>
    //  -c <opt_c_arg>
    //  -d
    char const * optstring = "ab:c:d";
    int opt_a = 0;
    char* opt_b = 0;
    char* opt_c = 0;
    int opt_d = 0;

    //オプションの解析
    int opt = 0;
    while((opt = getopt(argc, argv, optstring)) != -1) {
        switch(opt) {
        case 'a':
            opt_a = 1;
            break;
        case 'b':
            opt_b = optarg;
            break;
        case 'c':
            opt_c = optarg;
            break;
        case 'd':
            opt_d = 1;
            break;
        default:
            cerr << "unknown option." << endl;
            exit(-1);
            break;
        }
    }

    //オプション以外のパラメータ
    char* noptarg = argv[optind++];
}
```

### 使い方

main関数のargc,argvとオプション定義の文字列を渡して、(-1)が返されるまで繰り返し呼び出して、オプション解析を行います。

#### オプションの定義

オプションは、オプションの文字列を並べた文字列で定義。

引数を取るオプションは、オプション文字の次にコロンを記述。

#### 戻り値

(-1)はオプション解析が終了したことを表します。

オプションが見つかるとその文字を返します。

オプションでない文字が指定されているときは、'?'が返されます。

#### オプションの引数

引数を取るオプションが見つかった場合、`optarg`がその引数を指し示しています。

#### オプション以外のコマンドラインパラメータ

オプション解析が終了すると、グローバル変数 `optind` が、オプションでない最初のコマンドラインパラメータを指しています。
`optind < argc` なら、`argv[optind]`が、オプションではない最初のコマンドラインパラメータです。
`optind >= argc` なら、オプションでないパラメータはありません。

