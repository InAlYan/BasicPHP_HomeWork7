<p>Список пользователей в хранилище</p>
<form action="/user/edit" method="post">

<button name="action" value="+">+</button>

<ul id="navigation">
    {% for user in users %}
       <li>
          <a href="/user/edit/?id={{user.getUserId()}}">
             {{user.getUserId()}}.
             {{user.getUserName()}} {{user.getUserLastName()}}.
             {% if (user.getUserBirthday() is not same as (null)) %}
                День рождения: {{user.getUserBirthday() | date('d.m.Y')}}
             {% endif %}
          </a>
          <span>...</span>
          <button name="action" value="{{user.getUserId()}}">-</button>
       </li>
    {% endfor %}
</ul>
</form>