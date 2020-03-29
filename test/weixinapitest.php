<?php
/**
 * File: weixinapitest.php
 * Functionality:
 * Author: Li
 * Date: 2020/3/29
 */

error_reporting(E_ALL);
require_once '../vendor/autoload.php';

use echoyii\weixinapi;
$config = [
    'appid' => 'wxc2c6b51a8030a6ab',
    'token' => '27057a36f7e711e2841d00163e122bbb',
    'secret' => '30daf3af06d782d227f37f8a193638b2',
];
$wxapi = new weixinapi($config);
$menu_info = $wxapi->getMenu(1);
var_dump($menu_info);
exit();
