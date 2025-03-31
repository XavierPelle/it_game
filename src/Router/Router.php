<?php
class Router
{
    private $routes = [];

    public function addRoute($method, $path, $handler)
    {
        $this->routes[$method][$path] = $handler;
    }

    public function handleRequest()
    {
        $method = $_SERVER['REQUEST_METHOD'];
        $path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

        if (isset($this->routes[$method][$path])) {
            call_user_func($this->routes[$method][$path]);
        } else {
            $this->notFound();
        }
    }

    private function notFound()
    {
        http_response_code(404);
        echo json_encode(['error' => 'Route not found.']);
    }
}
