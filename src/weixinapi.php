<?php
/**
 * File: weixinapi.php
 * Functionality:
 * Author: Li
 * Date: 2020/3/29
 */

namespace echoyii;
class WeixinApi
{
    private static $_instance;
    private $weixinAccount;
    //weixn token parms
    private $config = [
        'appid' => 'wxc2c6b51a8030a6ab',
        'token' => '27057a36f7e711e2841d00163e122bbb',
        'secret' => '30daf3af06d782d227f37f8a193638b2',
    ];


    public function __construct($config = [])
    {
        if (!empty($config['secret'])) {
            $this->weixinAccount[1] = array_merge($this->config, $config);

        } elseif (is_array($config[1])) {
            $this->weixinAccount = $config;
        } else {
            $this->weixinAccount = [];
        }
    }

    public function __clone()
    {
        trigger_error('Clone is not allow!', E_USER_ERROR);
    }

    public static function getInstance($config = [])
    {
        if (!(self::$_instance instanceof self)) {
            self::$_instance = new self($config);
        }
        return self::$_instance;
    }

//======================================================================一、订阅号功能（创建菜单和消息接收与推送,也包含获取用户openid,准确的说是unionid）=============================================================================================
//=============1.1.接口验证=========================================
    /**
     * 接口验证-主域名和回调域名
     * @param unknown_type $_GET
     * @param bool
     */
    public function is_token()
    {
        $echoStr = $_GET["echostr"];
        $wid = 1;
        if ($this->checkSignature($wid)) {
            echo $echoStr;
            exit;
        }
    }

    //检测token
    private function checkSignature($wid = 1)
    {
        if (isset($this->weixinAccount[$wid])) {
            $token = $this->weixinAccount[$wid]['token'];
            $signature = $_GET["signature"];
            $timestamp = $_GET["timestamp"];
            $nonce = $_GET["nonce"];
            $tmpArr = array($token, $timestamp, $nonce);
            sort($tmpArr, SORT_STRING);
            $tmpStr = implode($tmpArr);
            $tmpStr = sha1($tmpStr);
            if ($tmpStr == $signature) {
                return true;
            } else {
                return false;
            }
        } else {
            return false;
        }
    }
//==============1.2.创建菜单========================================

    /**
     * 创建菜单 这里是本公众号的主域名和回调域名
     * @param openid ,appid,secret
     * @param 用户信息
     */
    public function creatMenu($data, $wid = 1)
    {
        if (isset($this->weixinAccount[$wid])) {
            $appid = $this->weixinAccount[$wid]['appid'];
            $secret = $this->weixinAccount[$wid]['secret'];
            #$appid="wx9a6c16699a107e35";
            #$secret="3105a0a9560277d1543b350ba5419490";
            $url = "https://api.weixin.qq.com/cgi-bin/menu/create?access_token=" . $this->getAccessToken($appid, $secret);
            $result = json_decode($this->https_request($url, $data));
            return $result;
        } else {
            return array();
        }
    }

    /**
     * 查询菜单(获取自定义菜单配置)
     * @param appid,secret
     * @return  查询结果
     */
    public function getMenu($wid = 1)
    {
        $result = array();
        if (isset($this->weixinAccount[$wid])) {
            $appid = $this->weixinAccount[$wid]['appid'];
            $secret = $this->weixinAccount[$wid]['secret'];

            $url = 'https://api.weixin.qq.com/cgi-bin/menu/get?access_token=' . $this->getAccessToken($appid, $secret);
            $result = json_decode(file_get_contents($url));
        } else {
            return array();
        }
        return $result;
    }
//==============1.3.接收消息========================================
    //发送消息给用户
    public function sendMsg($openid, $msg, $wid = 1)
    {
        if (isset($this->weixinAccount[$wid])) {
            $appid = $this->weixinAccount[$wid]['appid'];
            $secret = $this->weixinAccount[$wid]['secret'];

            $accesstoken = $this->getAccessToken($appid, $secret);
            if ($accesstoken) {
                $url = "https://api.weixin.qq.com/cgi-bin/message/custom/send?access_token={$accesstoken}";
                $jsonData = '{"touser":"' . $openid . '","msgtype":"text","text":{"content":"' . $msg . '"}}';
                $re = json_decode($this->JsonPost($url, $jsonData), true);
                if (is_array($re) AND isset($re['errcode']) AND (int)$re['errcode'] == 0) {
                    return array('code' => 1, 'msg' => $re['errmsg']);
                } else {
                    $msg = isset($re['errmsg']) ? $re['errmsg'] : '失败';
                    return array('code' => 0, 'msg' => $msg);
                }
            } else {
                return array('code' => 0, 'msg' => "获取accesstoken失败");
            }
        } else {
            return array('code' => 0, 'msg' => "不存在的公众号ID");
        }
    }

    //发送通知模板消息-参数
    public function sendTemplateMsg($params, $wid = 1)
    {
        if (isset($this->weixinAccount[$wid])) {
            $appid = $this->weixinAccount[$wid]['appid'];
            $secret = $this->weixinAccount[$wid]['secret'];

            $data = array();
            foreach ($params['data'] AS $k => $i) {
                $data[$k]['value'] = $i;
                $data[$k]['color'] = "#173177";
                if ($k == 'remark') {
                    $data[$k]['color'] = "#333333";
                }
            }
            //处理地址链接，如果不存在就用默认
            if (isset($params['url']) AND $params['url'] != '') {
                $click_url = $params['url'];
            } else {
                $click_url = '';
            }

            $items = array(
                'touser' => $params['touser'],
                'template_id' => $params['template_id'],
                'url' => $click_url,
                'topcolor' => '#FF0000',
                'data' => $data,
            );
            $json = json_encode($items);
            $accesstoken = $this->getAccessToken($appid, $secret);
            if ($accesstoken) {
                $url = "https://api.weixin.qq.com/cgi-bin/message/template/send?access_token=" . $accesstoken;
                $re = json_decode($this->JsonPost($url, $json), true);
                if (isset($re['errcode']) AND (int)$re['errcode'] == 0) {
                    return array('code' => 1, 'msg' => $re['errmsg']);
                } else {
                    return array('code' => 0, 'msg' => $re['errmsg']);
                }
            } else {
                return array('code' => 0, 'msg' => "获取accesstoken失败");
            }
        } else {
            return array('code' => 0, 'msg' => "不存在的公众号ID");
        }
    }
//======================================================================二、服务号登录与获取用户信息=============================================================================================

    /**
     * 第一步：用户同意授权，获取code 网页授权 这里是本公众号的主域名和回调域名 获取用户openid
     * @param unknown_type $appid
     * @param $uri 跳转地址
     */
    public function wxLogin_scope($uri, $wid = 1)
    {
        if (isset($this->weixinAccount[$wid])) {
            $appid = $this->weixinAccount[$wid]['appid'];

            $url = array(
                'appid' => $appid,
                'redirect_uri' => $uri,
                'response_type' => 'code',
                'scope' => 'snsapi_base',
                'state' => '1'
            );
            header('location:https://open.weixin.qq.com/connect/oauth2/authorize?' . http_build_query($url) . '#wechat_redirect');
            exit();
        } else {
            exit('error');
        }
    }

    /**
     * 第一步：用户同意授权，获取code 网页授权 网页授权 这里是本公众号的主域名和回调域名 获取用户基本信息
     * @param unknown_type $appid
     * @param $uri 跳转地址
     */
    public function wxLogin_User($uri, $wid = 1)
    {
        if (isset($this->weixinAccount[$wid])) {
            $appid = $this->weixinAccount[$wid]['appid'];
            $url = array('appid' => $appid,
                'redirect_uri' => $uri,
                'response_type' => 'code',
                'scope' => 'snsapi_userinfo',
                'state' => '1'
            );
            header('location:https://open.weixin.qq.com/connect/oauth2/authorize?' . http_build_query($url) . '#wechat_redirect');
            exit();
        } else {
            exit('error');
        }
    }

    /**
     * 第二步：通过code换取网页授权access_token 获取openid
     */
    public function getAuthorizes($wid = 1)
    {
        $result = array();
        if (isset($this->weixinAccount[$wid])) {
            $appid = $this->weixinAccount[$wid]['appid'];
            $secret = $this->weixinAccount[$wid]['secret'];
            $code = $_GET['code'];
            $state = $_GET['state'];
            if ($code) {
                //获取token
                $token_url = 'https://api.weixin.qq.com/sns/oauth2/access_token?appid=' . $appid . '&secret=' . $secret . '&code=' . $code . '&grant_type=authorization_code';
                $token = json_decode(file_get_contents($token_url));
                if (isset($token->errcode)) {

                    // echo '<h1>错误1：</h1>'.$token->errcode;
                    // echo '<br/><h2>错误信息：</h2>'.$token->errmsg;
                    // exit;
                } else {
                    $result['openid'] = $token->openid;
                    $result['unionid'] = $token->unionid;
                    $result['access_token'] = $token->access_token;
                    $result['appid'] = $appid;
                }
            }
        }
        return $result;
    }

    /**第四步：拉取用户信息(需scope为 snsapi_userinfo)
     * 获取手机端网页登录授权
     */
    public function getAuthorizesUser($wid)
    {
        $result = array();
        if (isset($this->weixinAccount[$wid])) {
            $appid = $this->weixinAccount[$wid]['appid'];
            $secret = $this->weixinAccount[$wid]['secret'];

            $code = $_GET['code'];
            $state = $_GET['state'];

            if ($code) {
                //获取token
                $token_url = 'https://api.weixin.qq.com/sns/oauth2/access_token?appid=' . $appid . '&secret=' . $secret . '&code=' . $code . '&grant_type=authorization_code';
                $token = json_decode(file_get_contents($token_url));
                if (isset($token->errcode)) {
                    /*echo '<h1>错误1：</h1>'.$token->errcode;
                    echo '<br/><h2>错误信息：</h2>'.$token->errmsg;
                    exit;*/
                } else {
                    $access_token = $token->access_token;
                    $openid = $token->openid;
                    if ($access_token AND $openid) {
                        //拉去信息
                        $user_info_url = 'https://api.weixin.qq.com/sns/userinfo?access_token=' . $access_token . '&openid=' . $openid . '&lang=zh_CN';
                        $user_info = json_decode(file_get_contents($user_info_url), true);
                        if (isset($user_info['errcode'])) {
                            /*echo '<h1>错误2：</h1>'.$user_info['errcode'];
                            echo '<br/><h2>错误信息：</h2>'.$user_info['errmsg'];
                            exit;*/
                        } else {
                            $result = $user_info;
                        }
                    }
                }
            }
        }
        return $result;
    }

    /**
     * 获取用户基本信息（包括UnionID机制） 已关注用户才能获取此信息
     * @param openid ,appid,secret
     * @param 用户信息
     */
    public function getWeixinUser($openid, $wid = 1, $new = 0)
    {
        $result = array();
        if (isset($this->weixinAccount[$wid]) AND $openid) {
            $appid = $this->weixinAccount[$wid]['appid'];
            $secret = $this->weixinAccount[$wid]['secret'];

            $accesstoken = $this->getAccessToken($appid, $secret, $new);
            if ($accesstoken) {
                $api = "https://api.weixin.qq.com/cgi-bin/user/info?access_token={$accesstoken}&openid={$openid}&lang=zh_CN";
                $result = json_decode(file_get_contents($api), true);
                if (isset($result['errcode'])) {
                    if ($result['errcode'] == '40001') {
                        //这里是因为token过期了
                        return $this->getWeixinUser($openid, $wid, 1);
                    }
                }
            }
        }
        return $result;
    }
//======================================================================三、分享用的JS安全域名=============================================================================================

    /**
     * JS安全域名操作 支持多公众号
     * @param openid ,appid,secret
     * @param 用户信息
     */
    public function getSignPackage($wid = 1)
    {
        $result = array();
        if (isset($this->weixinAccount[$wid])) {
            $appid = $this->weixinAccount[$wid]['appid'];
            $secret = $this->weixinAccount[$wid]['secret'];
            $jsapiTicket = $this->getJsApiTicket($appid, $secret);
            if (is_array($jsapiTicket) AND isset($jsapiTicket['code'])) {
                return $result;
            }
            // 注意 URL 一定要动态获取，不能 hardcode.
            //$protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off' || $_SERVER['SERVER_PORT'] == 443) ? "https://" : "http://";
            $protocol = "https://";
            $url = "$protocol$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]";
            $timestamp = time();
            $nonceStr = $this->createNonceStr();
            // 这里参数的顺序要按照 key 值 ASCII 码升序排序
            $string = "jsapi_ticket=$jsapiTicket&noncestr=$nonceStr&timestamp=$timestamp&url=$url";
            $signature = sha1($string);
            $result = array(
                "appId" => $appid,
                "nonceStr" => $nonceStr,
                "timestamp" => $timestamp,
                "url" => $url,
                "signature" => $signature,
                "rawString" => $string
            );
        }
        return $result;
    }

    private function getJsApiTicket($appid, $secret)
    {
        $data = $config = array();
        $file_path = TEMP_PATH . "/{$appid}-jsapi_ticket.json";
        if (file_exists($file_path)) {
            $data = json_decode(file_get_contents($file_path), true);
        }
        //取旧值
        if (!empty($data) AND isset($data['config']) AND (isset($data['expire_time']) AND $data['expire_time'] < time())) {
            $config = $data['config'];
        } else {
            $config = array();
        }

        if (empty($config)) {
            $accessToken = $this->getAccessToken($appid, $secret);
            $url = "https://api.weixin.qq.com/cgi-bin/ticket/getticket?type=jsapi&access_token={$accessToken}";
            $result = json_decode($this->httpGet($url));
            if ($result->ticket) {
                $data = array();
                $data['expire_time'] = time() + 6500;
                $data['config'] = $config = $result->ticket;
                $fp = fopen($file_path, "w");
                fwrite($fp, json_encode($data));
                fclose($fp);
            } else {
                return array('code' => $result->errcode, 'msg' => $result->errmsg);
            }
        }
        return $config;
    }

    private function createNonceStr($length = 16)
    {
        $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        $str = "";
        for ($i = 0; $i < $length; $i++) {
            $str .= substr($chars, mt_rand(0, strlen($chars) - 1), 1);
        }
        return $str;
    }

//======================================================================四、创建二维码=============================================================================================
    public function creatQrcode($id, $type = true, $wid = 1)
    {
        $result = '';
        if (isset($this->weixinAccount[$wid])) {
            $appid = $this->weixinAccount[$wid]['appid'];
            $secret = $this->weixinAccount[$wid]['secret'];

            $access_token = $this->getAccessToken($appid, $secret);
            if ($access_token) {
                if ($type) {
                    $tempJson = '{"action_name": "QR_LIMIT_SCENE", "action_info": {"scene": {"scene_id":' . $id . '}}}';
                } else {
                    $tempJson = '{"expire_seconds": 604800, "action_name": "QR_SCENE", "action_info": {"scene": {"scene_id": ' . $id . '}}}';
                }
                $url = "https://api.weixin.qq.com/cgi-bin/qrcode/create?access_token=" . $access_token;
                $tempArrs = json_decode($this->JsonPost($url, $tempJson), true);
                if ($tempArrs['errcode']) {
                    echo '获取二维码错误' . $tempArrs['errcode'];
                    exit;
                }
                $result = 'https://mp.weixin.qq.com/cgi-bin/showqrcode?ticket=' . urlencode($tempArrs['ticket']);
            }
        }
        return $result;
    }
//======================================================================五、私有公共函数与方法=============================================================================================
//==============5.1获取token========================================
    /**
     * 微信端接口获取token用 需要支持多域名多公众号
     * @param appid ,secret
     * @param tokey
     */
    public function getAccessToken($appid, $secret, $new = 0)
    {
        if (DEBUG) {
            return '';
        }
        $data = $config = array();
        $file_path = TEMP_PATH . "/{$appid}-token.json";
        if (file_exists($file_path) AND !$new) {
            $data = json_decode(file_get_contents($file_path), true);
        }
        //取旧值
        if (!empty($data) AND isset($data['config'])) {
            $config = $data['config'];
        }
        // echo $config;die;
        if (empty($config) OR (isset($data['expire_time']) AND $data['expire_time'] < time()) OR $new) {
            // $api = "https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid={$appid}&secret={$secret}";
            // $result = json_decode(file_get_contents($api));
            // if (isset($result->errcode)) {
            //     echo '<h1>错误token：</h1>'.$result->errcode;
            //     echo '<br/><h2>错误信息token：</h2>'.$result->errmsg;
            //     exit;
            // } else {
            //     $data = array();
            //     $data['expire_time'] = time() + 6500;
            //     $data['config'] = $config = $result->access_token;
            //     $fp = fopen($file_path, "w");
            //     fwrite($fp, json_encode($data));
            //     fclose($fp);
            // }
            //调用移动端中控服务access_token
            $url = HOME_URL . "mobile/Sitetoken/getaccesstoken?signature=" . $this->createToken();
            // echo $url;die;
            $res = json_decode(file_get_contents($url), true);
            // var_dump($res);
            if ($res['code'] == 0) {
                echo json_encode(['code' => 0, 'msg' => '接口验证失败', 'data' => '']);
                exit;
            } else {
                $data = ['code' => 1, 'msg' => '数据获取成功', 'data' => $res['data']];
                $config = $res['data']['config'];
                $fp = fopen($file_path, "w");
                fwrite($fp, json_encode($res['data']));
                fclose($fp);
            }
        }
        return $config;
    }

    //生成JWT token
    private function createToken()
    {
        $serverPrivateKey = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAKrU5gne1HvK18yk9aFX+LIgf8bIZvW/TgAAQWUkLkVDf1s91r6JmlmJsvGDz1KWuFEtU5k+ZTY+znh0ncLfgdTcmVvymp1D4fhEKt/JSaZNZe7Fb3kfl7iT15pQBivirrkpP1dwyM5EzafkRo5wKOktbQLYglW/e+ChVf4L+mqXAgMBAAECgYBcweb6Wwzi/rv4OWXKKps2FSFsTSpiq3Jt27WmdmPNZh4D6+rrYIn3riYEr35mKMKCCWuIHPIV5zpy+1ciFfxHNifvwVs9zpWGYkuvyI2Ar41zODI8doYFaQjWUBf/xJziabTEn1pFsH+Q8xWqr0fXdFdKYt6lYnjZR3bJIL79yQJBANaEQ0MqPqbj4s6L++igcgizkPOQ00a0kRdv6R0wQWqXg5fseg776sUv301XYbTnc7BlmHsQUQsYcROOqzhZlNsCQQDL3f2ehMGecX2qnImBGbXIRIIF1DnjULDzBpz/ijMYg1trIRRjBirWFj6cQOEOxlW2A8qpz1ZxR9zfSzjYXG/1AkBPn8xvs9CJlfDsBd29XUC2piBZqBokFoX8kxeONAk0DYVU8Pvlb/CWvMxAIv0rbvXsNenBVC8g1TOztLMtOWMdAkEAgC1ZyXHknm7yuPNkzOPSVFEmgu21W8OfDZ2p1k0Y5R+puch5ne0Bv8sKoIl2NyjiOOdXY761tdGeAFK2MeqkhQJALGjfBtrV9c3u3XVVbpASadkkOcUvXOb8fyRvTv03Bg3cbF3hP6ucb5SPEg6dDHixRj25S+JTiYH5WxbtyYni5g==";
        $tokenKey = array(
            "iss" => "https://m.zrchefu.com",  //jwt签发者
            "aud" => 'WX',                     //接收jwt的一方
            "exp" => time() + 60,               //过期时间
        );
        return JWT::encode($tokenKey, self::readRSAKey($serverPrivateKey), 'RS256');
    }

    //为JWT准备的，证书处理函数
    private static function readRSAKey($key)
    {
        $isPrivate = strlen($key) > 500;
        if ($isPrivate) {
            $lastKey = chunk_split($key, 64, "\n");
            $lastKey = "-----BEGIN RSA PRIVATE KEY-----\n" . $lastKey . "-----END RSA PRIVATE KEY-----\n";
            return $lastKey;
        } else {
            $lastKey = chunk_split($key, 64, "\n");
            $lastKey = "-----BEGIN PUBLIC KEY-----\n" . $lastKey . "-----END PUBLIC KEY-----\n";
            return $lastKey;
        }
    }

//==============5.2 CRUL方法========================================
    private function JsonPost($url, $jsonData)
    {
        $curl = curl_init();
        curl_setopt($curl, CURLOPT_URL, $url);
        curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, FALSE);
        curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, FALSE);
        curl_setopt($curl, CURLOPT_POST, 1);
        curl_setopt($curl, CURLOPT_POSTFIELDS, $jsonData);
        curl_setopt($curl, CURLOPT_TIMEOUT, 30);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
        $result = curl_exec($curl);
        if (curl_errno($curl)) {
            error_log('curl falied. Error Info: ' . curl_error($curl));
        }
        curl_close($curl);
        return $result;
    }

    private function https_request($url, $data = null)
    {
        $curl = curl_init();
        curl_setopt($curl, CURLOPT_URL, $url);
        curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, FALSE);
        curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, FALSE);
        if (!empty($data)) {
            curl_setopt($curl, CURLOPT_POST, 1);
            curl_setopt($curl, CURLOPT_POSTFIELDS, $data);
        }
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
        $output = curl_exec($curl);
        curl_close($curl);
        return $output;
    }

    private function httpGet($url)
    {
        $curl = curl_init();
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_TIMEOUT, 500);
        curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($curl, CURLOPT_URL, $url);

        $res = curl_exec($curl);
        curl_close($curl);

        return $res;
    }

}