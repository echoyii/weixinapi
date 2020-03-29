# weixinapi
微信api主要用于微信公众号的接口调用，如创建公众号菜单，模板消息，创建二维码
#用法示例
1)eg:
use echoyii\weixinapi;
$config = [
    'appid' => 'wxc2c6b51a8030a6ab',
    'token' => '27057a36f7e711e2841d00163e122bbb',
    'secret' => '30daf3af06d782d227f37f8a193638b2'
];
//测试
$wxapi = weixinapi::getInstance($config);
$menu_info = $wxapi->getMenu();
var_dump($menu_info);
exit();

2)eg:
use echoyii\weixinapi;

$config[1] = [
    'appid' => 'wxc2c6b51a8030a6ab',
    'token' => '27057a36f7e711e2841d00163e122bbb',
    'secret' => '30daf3af06d782d227f37f8a193638b2',
];

//测试
$wxapi = weixinapi::getInstance($config);
$params = [];//模板消息参数
$menu_info = $wxapi->sendTemplateMsg($params);
var_dump($menu_info);
exit();