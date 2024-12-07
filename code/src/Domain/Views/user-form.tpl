<h2>{{message}}</h2>

<form action="/user/{{action}}" method="post">
    <input id="csrf_token" type="hidden" name="csrf_token" value="{{csrf_token}}">
    <input id="id-user" type="hidden" name="id_user" value="{{user.getUserId()}}">
    <p>
        <label for="user-name">Имя:</label>
        <input id="user-name" type="text" name="name" value="{{user.getUserName()}}">
    </p>
    <p>
        <label for="user-lastname">Фамилия:</label>
        <input id="user-lastname" type="text" name="lastname" value="{{user.getUserLastName()}}">
    </p>
    <p>
        <label for="user-birthday">День рождения:</label>
        <input id="user-birthday" type="text" name="birthday" placeholder="ДД-ММ-ГГГГ" value="{% if (user.getUserBirthday() is not same as (null)) %}{{user.getUserBirthday() | date('d-m-Y')}}{% endif %}">
    </p>
    <p>
        <input type="submit" value="Сохранить"
    </p>
</form>