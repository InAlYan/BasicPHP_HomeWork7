<h3>{{ message }}</h3>

<ul>
    {% if (user.getUserId() is not same as (null)) %}
        <li>Id: {{user.getUserId()}} </li>
    {% endif %}
    <li>Имя: {{user.getUserName()}}</li>
    <li>Фамилия: {{user.getUserLastName()}}</li>
    {% if (user.getUserBirthday() is not same as (null)) %}
        <li>День рождения: {{user.getUserBirthday() | date('d.m.Y')}} </li>
    {% endif %}
</ul>