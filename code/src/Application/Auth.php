<?php

namespace Geekbrains\Application1\Application;

use Geekbrains\Application1\Domain\Models\User;
use PDO;

class Auth
{
    public static function getPasswordHash(string $rawPassword): string {
        return password_hash($_GET['pass_string'], PASSWORD_BCRYPT);
    }

    public function proceedAuth(string $login, string $password, bool $saveMe=false): bool {
        $sql = "SELECT id_user, user_name, user_lastname, password_hash, hash FROM users WHERE login = :login";

        $handler = Application::$storage->get()->prepare($sql);
        $handler->execute(['login' => $login]);
        $result = $handler->fetchAll();

        if (!empty($result) && password_verify($password, $result[0]['password_hash'])) {

            $this->fillSessionDataByUserData($result[0]['user_name'],
                                             $result[0]['user_lastname'],
                                             $result[0]['id_user']
            );

            // Здесь устанавливаем куку токен пользователя user-token, а также записать в базу в таблицу users поле hash
            if ($saveMe){
                // Создаем токен
                $userToken = $this->generateToken();
                // Пишем созданный токен в куки user-token
                setcookie("user-token", $userToken, time() + 60 * 60 * 12 * 1, '/');
                // Пишем токен в таблицу users в поле hash
                User::setToken($result[0]['id_user'], $userToken);
            }

            return true;
        }
        return false;
    }

    public function generateToken() {
        return bin2hex(random_bytes(32));
    }

    public function fillSessionDataByUserData($userName, $userLastName, $userId) {
        $_SESSION['user_name'] = $userName;
        $_SESSION['user_lastname'] = $userLastName;
        $_SESSION['id_user'] = $userId;
    }

    public function restoreSession() {

        // Если кука с user-token существует и сессия не существует
        if (isset($_COOKIE['user-token']) && !isset($_SESSION['id_user'])) {

            // Если пользователь с таким user-token существует
            if (User::tokenExist($_COOKIE['user-token'])) {
                // Получаем пользователя с таким user-token
                $user = User::getUserFromStorageByToken($_COOKIE['user-token']);
                // Наполняем сессию данными
                $this->fillSessionDataByUserData($user->getUserName(),
                                                 $user->getUserLastName(),
                                                 $user->getUserId()
                );
            }
        }
    }

}