<?php

namespace Geekbrains\Application1\Domain\Models;

class Time {
    public static function getCurrentTime() {
        return date('m/d/Y h:i:s a', time());
    }
}