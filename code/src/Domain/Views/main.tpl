<!DOCTYPE html>
<link rel="stylesheet" href="/src/css/main.css">
<html>
    <head>
        <title>{{ title }}</title>
    </head>
    <body>
        <div> {{ content_template_cur_time }} </div>
        <div>{% include "auth.tpl" %}</div>
        <div>{% include content_template_header %}</div>
        <div>{% include content_template_name %}</div>
        <div>{% include content_template_sidebar %}</div>
        <div>{% include content_template_footer %}</div>
    </body>
</html>