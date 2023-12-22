# myUtil
工作常用的一些工具类
# CryptographyUtil
一个java工具类，用于验证和生成基于微软 .NET Core 的认证密码。
- 生成形如：AQAAAAEAACcQAAAAEF4Pl6+QJUoFPpxmkTTnCtishhyEHCzFGgjTlN058tIV8hkaVV8i20CsUtJu5MdrYw== 这样的密码
- String getCryString(String pwd) 生成密码
- boolean verifyCryString(String pwd, String pwdHash) 验证密码是否正确
