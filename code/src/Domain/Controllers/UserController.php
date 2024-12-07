<?php

namespace Geekbrains\Application1\Domain\Controllers;

use Geekbrains\Application1\Application\Application;
use Geekbrains\Application1\Application\Auth;
use Geekbrains\Application1\Application\Render;
use Geekbrains\Application1\Domain\Models\User;
use Geekbrains\Application1\Domain\Controllers\AbstractController;

class UserController extends AbstractController {

    protected array $actionsPermissions = [
        'actionHash' => ['admin', 'manager'],
        'actionSave' => ['admin'],
        'actionUpdate' => ['admin'],
        'actionEdit' => ['admin'],
        'actionIndex' => ['admin', 'user'],
        'actionShow' => ['admin'],
        'actionLogout' => ['admin', 'user'],
    ];

    public function actionIndex(): string {
        $users = User::getAllUsersFromStorage();

        $render = new Render();

        if(!$users){
            return $render->renderPage(
                'user-empty.tpl',
                [
                    'title' => 'Список пользователей в хранилище',
                    'message' => "Список пуст или не найден"
                ]);
        }
        else{
            return $render->renderPage(
                'user-index.tpl', 
                [
                    'title' => 'Список пользователей в хранилище',
                    'users' => $users
                ]);
        }
    }

    public function actionSave() {
        if(User::validateRequestData()) {
            $user = new User();
            $user->setParamsFromRequestData();
            $user->saveToStorage();

             header('Location: ' . '/user');
        }
        else {
            throw new \Exception("Переданные данные некорректны");
        }
    }

    public function actionUpdate() {
        $id =  $this->postCorrectedId();

        if(User::exists($id)) {
            $user = new User();
            $user->setUserId($id);
            
            $arrayData = [];

            if(isset($_POST['name'])) $arrayData['user_name'] = $_POST['name'];
            if(isset($_POST['lastname'])) $arrayData['user_lastname'] = $_POST['lastname'];
            if(isset($_POST['birthday'])) $arrayData['user_birthday_timestamp'] = $_POST['birthday'];

            $user->updateUser($arrayData);

            header('Location: ' . '/user');
        }
        else {
            throw new \Exception("Пользователь не существует");
        }
    }

    public function actionDelete() {

        $id = $this->getCorrectedId();

        if(User::exists($id)) {
            User::deleteFromStorage($id);

             header('Location: ' . '/user');
        }
        else {
            throw new \Exception("Пользователь не существует");
        }
    }

    public function actionShow(): string {

        $id = $this->getCorrectedId();

        if(User::exists($id)) {
            $user = User::getUserFromStorageById($id);

            $render = new Render();
            return $render->renderPage(
                'user-created.tpl', [
                    'title' => 'Создан новый пользователь',
                    'message' => "Новый пользователь ",
                    'user' => $user
                ]
            );
        }
        else {
            throw new \Exception("Пользователь с таким id не существует");
        }
    }

    public function actionEdit() {

        $id = $this->getCorrectedId();

        // Удаление пользователя
        If (isset($_POST['action']) && $_POST['action'] != '+') {

            $id = $_POST['action'];

            if(User::exists($id)) {
                User::deleteFromStorage($id);
                header('Location: ' . '/user');
                die();
            }
            else {
                throw new \Exception("Пользователь не существует");
            }
        }

        // Редактирование пользователя
        if(User::exists($id)) {

            $user = User::getUserFromStorageById($id);

            $render = new Render();
            return $render->renderPageWithForm("user-form.tpl",
                [
                    'title' => 'Изменение пользователя',
                    'message' => 'Изменение пользователя',
                    'user' => $user,
                    'action' => 'update'
                ]);
        }
        // Создание пользователя
        else {

            $render = new Render();
            return $render->renderPageWithForm("user-form.tpl",
                [
                    'title' => 'Новый пользователь',
                    'message' => "Новый пользователь",
                    'action' => 'save'
                ]);
        }
    }

    private function getCorrectedId(): int
    {
        return (isset($_GET['id'])) ? (int)$_GET['id'] : 0;
    }

    private function postCorrectedId(): int
    {
        return (isset($_POST['id_user'])) ? (int)$_POST['id_user'] : 0;
    }

    public function actionHash(): string {
        return Auth::getPasswordHash($_GET['pass_string']);
    }

    public function actionAuth(): string {
        $render = new Render();
        return $render->renderPageWithForm('user-auth.tpl',
        [
            'title' => 'Форма логина'
        ]);
    }

    public function actionLogin(): string {

        $result =false;

        if (isset($_POST['login']) && isset($_POST['password'])) {
            // Если checkbox "сохранить" установлен передаем параметром в процедуру аутентификации
            $result = Application::$auth->proceedAuth($_POST['login'], $_POST['password'], isset($_POST['user-remember']));
        }

        if (!$result) {
            $render = new Render();
            return $render->renderPageWithForm('user-auth.tpl',
                [
                    'title' => 'Форма логина',
                    'auth-success' => false,
                    'auth-error' => 'Неверные логин и (или) пароль'
                ]);
        } else {
            header('Location: /');
            return "";
        }
    }

    public function actionLogout(): void {
        session_destroy();
        unset($_SESSION['user_name']);
        unset($_SESSION['user_lastname']);
        unset($_SESSION['id_user']);
        unset($_SESSION['csrf_token']);

        if (isset($_COOKIE['user-token'])) {
            unset($_COOKIE['user-token']);
            setcookie('user-token', '', -1, '/');
        }

        header('Location: /');
        die();
    }

}