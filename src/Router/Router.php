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

    error_log("Méthode: $method, URI: $path"); // <-- déjà ajouté, très bien

    if (isset($this->routes[$method][$path])) {
        error_log("Route trouvée, exécution de : " . json_encode($this->routes[$method][$path]));
        call_user_func($this->routes[$method][$path]);
    } else {
        error_log("Route non trouvée : $method $path");
        $this->notFound();
    }
}



    private function notFound()
    {
        http_response_code(404);
        echo json_encode(['error' => 'Route not found.']);
    }
}
