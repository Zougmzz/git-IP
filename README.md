# git-IP
定时获取指定域名的IP地址
    做这个项目的初衷是我访问某些网站时，时常连接不稳定。因此而翻墙有点小题大做 Ps：麻烦
所以
    我做了一个修改本地hosts的脚本，事实上这是迭代三个版本后的产物。
    在最开始我只是做了一个本地运行的脚本，但效果不是很理想。有许多网站的域名在特定网络下找不到合适的、可连接的IP。于是我换了一个思路，用github获取IP再由本地Ping测试延迟，以此达到最佳的网络体验。
