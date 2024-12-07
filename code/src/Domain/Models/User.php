<?php

namespace Geekbrains\Application1\Domain\Models;

use Geekbrains\Application1\Application\Application;
use Geekbrains\Application1\Infrastructure\Storage;

class User {

    private ?int $idUser;

    private ?string $userName;

    private ?string $userLastName;
    private ?int $userBirthday;

    private static string $storageAddress = '/storage/birthdays.txt';

    public function __construct(string $name = null, string $lastName = null, int $birthday = null, int $id_user = null){
        $this->userName = $name;
        $this->userLastName = $lastName;
        $this->userBirthday = $birthday;
        $this->idUser = $id_user;
    }

    public function setUserId(int $id_user): void {
        $this->idUser = $id_user;
    }

    public function getUserId(): ?int {
        return $this->idUser;
    }

    public function setName(string $userName) : void {
        $this->userName = $userName;
    }

    public function setLastName(string $userLastName) : void {
        $this->userLastName = $userLastName;
    }

    public function getUserName() {
        return $this->userName;
    }

    public function getUserLastName() {
        return $this->userLastName;
    }

    public function getUserBirthday() {
        return $this->userBirthday;
    }

    public function setBirthdayFromString(string $birthdayString) : void {
        $this->userBirthday = strtotime($birthdayString);
    }

    public static function getUserFromStorageById($id): User {
        $sql = "SELECT * FROM users WHERE id_user = :idUser";
        $handler = Application::$storage->get()->prepare($sql);
        $handler->execute(['idUser' => $id]);
        $user = $handler->fetch();
        return new User($user["user_name"],
                        $user["user_lastname"],
                        $user["user_birthday_timestamp"],
                        $user["id_user"]);
    }

    public static function getAllUsersFromStorage(): array {
        $sql = "SELECT * FROM users";

        $handler = Application::$storage->get()->prepare($sql);
        $handler->execute();
        $result = $handler->fetchAll();

        $users = [];

        foreach($result as $item){
            $user = new User($item['user_name'], $item['user_lastname'], $item['user_birthday_timestamp'],$item['id_user']);
            $users[] = $user;
        }

        return $users;
    }

    public static function validateRequestData(): bool{

        $result = true;

        if(
            !(isset($_POST['name']) && !empty($_POST['name']) &&
            isset($_POST['lastname']) && !empty($_POST['lastname']) &&
            isset($_POST['birthday']) && !empty($_POST['birthday']))
        ){
            $result = false;
        }
        if (!preg_match('/^(\d{2}-\d{2}-\d{4})$/', $_POST['birthday'])) {
            $result = false;
        }
        if (preg_match('/<([^>]*)>/', $_POST['name']) ||
            preg_match('/<([^>]*)>/', $_POST['lastname']) ||
            preg_match('/<([^>]*)>/', $_POST['lastname']))
        {
            $result = false;
        }
        if (!isset($_SESSION['csrf_token']) || $_SESSION['csrf_token'] != $_POST['csrf_token']) {
            $result = false;
        }

        return $result;
    }

    public function setParamsFromRequestData(): void {
        $this->userName = htmlspecialchars($_POST['name']);
        $this->userLastName = htmlspecialchars($_POST['lastname']);
        $this->setBirthdayFromString($_POST['birthday']);
    }

    public function saveToStorage(){

        $sql = "INSERT INTO users(user_name, user_lastname, user_birthday_timestamp) VALUES (:user_name, :user_lastname, :user_birthday)";

        $handler = Application::$storage->get()->prepare($sql);
        $handler->execute([
            'user_name' => $_POST['name'],
            'user_lastname' => $_POST['lastname'],
            'user_birthday' => strtotime($_POST['birthday'])
        ]);
    }

    public static function exists(int $id): bool{
        $sql = "SELECT count(id_user) as user_count FROM users WHERE id_user = :id_user";

        $handler = Application::$storage->get()->prepare($sql);
        $handler->execute([
            'id_user' => $id
        ]);

        $result = $handler->fetchAll();

        if(count($result) > 0 && $result[0]['user_count'] > 0){
            return true;
        }
        else{
            return false;
        }
    }

    public function updateUser(array $userDataArray) {
        $sql = "UPDATE users SET ";

        $counter = 0;
        foreach($userDataArray as $key => $value) {
            $sql .= $key ." = :".$key;

            if($counter != count($userDataArray)-1) {
                $sql .= ",";
            }

            $counter++;
        }
        $sql .= " WHERE id_user = :id_user";

        $userDataArray['id_user'] = $this->idUser;

        if(isset($userDataArray['user_birthday_timestamp'])) {
            $this->setBirthdayFromString($userDataArray['user_birthday_timestamp']);
            $userDataArray['user_birthday_timestamp'] = $this->userBirthday;
        }

        $handler = Application::$storage->get()->prepare($sql);
        $handler->execute($userDataArray);
    }

    public static function deleteFromStorage(int $user_id) : void {
        $sql = "DELETE FROM users WHERE id_user = :id_user";

        $handler = Application::$storage->get()->prepare($sql);
        $handler->execute(['id_user' => $user_id]);
    }

    public static function getUserRoleById() {

        $sql = "SELECT * FROM user_roles WHERE id_user = :id_user";
        $handler = Application::$storage->get()->prepare($sql);
        $handler->execute(['id_user' => $_SESSION['id_user']]);

        $queryResult = $handler->fetchAll();

        $roles =[];

        foreach ($queryResult as $item) {
            $roles[] = $item['role'];
        }

        return $roles;
    }

    public static function setToken($id_user ,$token) {
        $sql = "UPDATE users SET hash = :token WHERE id_user = :id_user";

        $handler = Application::$storage->get()->prepare($sql);
        $handler->execute(['id_user' => $id_user, 'token' => $token]);
    }

    public static function tokenExist($token): bool {
        $sql = "SELECT hash FROM users WHERE hash = :hash";

        $handler = Application::$storage->get()->prepare($sql);
        $handler->execute(['hash' => $token]);

        $result = $handler->fetchAll();

        return count($result) > 0;
    }

    public static function getUserFromStorageByToken($token): User {
        $sql = "SELECT * FROM users WHERE hash = :token";
        $handler = Application::$storage->get()->prepare($sql);
        $handler->execute(['token' => $token]);
        $user = $handler->fetch();
        return new User($user["user_name"],
            $user["user_lastname"],
            $user["user_birthday_timestamp"],
            $user["id_user"]);
    }

}