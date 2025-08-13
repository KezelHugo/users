# 📦 Proyecto Final — Sistema de Gestión de Productos con Usuarios y Roles

## 📜 Contexto
La empresa ficticia **CompuStore** requiere un sistema compuesto por dos microservicios que permita **autenticación de usuarios con JWT** y **gestión de productos** con control de acceso por roles.

---

## 🎯 Objetivos del sistema
- Permitir que los usuarios se **registren** y **autentiquen** mediante **JWT**.
- Definir **roles**:
  - **ADMIN** → puede crear, editar y eliminar productos.
  - **CLIENT** → puede listar y ver detalles de productos, pero no modificarlos.
- Proteger los endpoints con **Spring Security** y validación de tokens entre microservicios.

---

## 🖥 Microservicio 1: `users-service`

### Endpoints obligatorios
1. **POST** `/api/users/register` → Registro de usuario.
2. **POST** `/api/users/login` → Autenticación y generación de token JWT.
3. **GET** `/api/users/profile` → Obtiene el perfil del usuario autenticado *(requiere token válido)*.

### Requisitos técnicos
- Spring Boot con Spring Security.
- Autenticación con **JWT**.
- Base de datos **MySQL** para guardar usuarios.
- Roles: `ADMIN` y `CLIENT`.
- Endpoint `/profile` solo accesible si el token es válido.

---

## 📦 Microservicio 2: `products-service`

### Endpoints obligatorios
1. **GET** `/api/products` → Lista todos los productos *(rol: CLIENT o ADMIN)*.
2. **GET** `/api/products/{id}` → Muestra detalle de un producto *(rol: CLIENT o ADMIN)*.
3. **POST** `/api/products` → Crea un producto *(rol: ADMIN)*.
4. **PUT** `/api/products/{id}` → Actualiza un producto *(rol: ADMIN)*.
5. **DELETE** `/api/products/{id}` → Elimina un producto *(rol: ADMIN)*.

### Requisitos técnicos
- Spring Boot con Spring Security.
- Validar **JWT** emitido por `users-service`.
- Base de datos **MySQL** con tabla de productos.

---

## 🔒 Seguridad y JWT
1. El token **JWT** se genera en el `users-service`.
2. El `products-service` debe validar el token antes de procesar cualquier petición.
3. Si el token es inválido o el usuario no tiene permisos, responder con:
   - **401 Unauthorized**
   - **403 Forbidden**

---

## 📄 Documentación con Swagger
- Ambos microservicios deben incluir **Swagger/OpenAPI** (`springdoc-openapi`).
- Deben permitir agregar el **JWT** en Swagger para probar endpoints protegidos.
- Personalizar el título y la descripción de la API.

---

## 🔄 Ejemplo de flujo

### 1️⃣ Registro de usuario en `users-service`
```http
POST /api/users/register
Content-Type: application/json

{
  "username": "juan",
  "password": "1234",
  "role": "CLIENT"
}
```

### 2️⃣ Login para obtener token
```http
POST /api/users/login
Content-Type: application/json

{
  "username": "juan",
  "password": "1234"
}
```
**Respuesta:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI..."
}
```

### 3️⃣ Usar token para acceder a `products-service`
```http
GET /api/products
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI...
```

### 4️⃣ Control de permisos
- Si el usuario es **ADMIN**, podrá crear/editar/eliminar productos.
- Si es **CLIENT**, solo podrá ver la lista y detalles de productos.

---

## ⚙️ Tecnologías utilizadas
- **Java 17+**
- **Spring Boot**
- **Spring Security**
- **JWT**
- **MySQL**
- **Spring Data JPA**
- **Swagger / OpenAPI**
- **Maven**

---

## 🚀 Ejecución del proyecto
1. Clonar el repositorio:
```bash
git clone https://github.com/usuario/repositorio.git
```
2. Entrar al microservicio deseado y ejecutar:
```bash
mvn spring-boot:run
```
3. Probar endpoints en Swagger:
```
http://localhost:8080/swagger-ui.html
```

---

## 🔍 Análisis de Calidad con SonarQube

Se ejecutaron análisis de calidad de código usando **SonarQube**, identificando y corrigiendo vulnerabilidades, errores y *code smells* para mejorar la mantenibilidad y seguridad del sistema.

### Principales mejoras aplicadas:
- **Optimización de Streams en Java**  
  - Se reemplazó el uso de `collect(Collectors.toList())` por `toList()` en streams, mejorando la legibilidad y eliminando código innecesario.
- **Seguridad en configuración de Spring Security**  
  - Se revisó y documentó la desactivación de CSRF para asegurar que solo se aplique en contextos seguros.
- **Pruebas unitarias limpias**  
  - Se añadieron comentarios en métodos de prueba vacíos para justificar su uso o se lanzaron excepciones `UnsupportedOperationException` cuando era necesario.
- **Eliminación de modificadores innecesarios**  
  - Se retiraron modificadores como `public` en clases de prueba que no los requerían.
- **Refactorización de clases utilitarias**  
  - Se ajustó `UserMapper` para que no sea instanciado como *bean* innecesario y se mantenga como clase de utilidades estática.
- **Mejora en la inyección de dependencias para pruebas**  
  - Se corrigieron anotaciones de `@TestConfiguration` y se resolvieron importaciones para asegurar que las pruebas funcionen correctamente.
 
![Sonar-results](assets/sonar_results.png)

### Resultado del análisis:
- **0 Vulnerabilidades críticas**  
- **0 Bugs detectados por SonarQube**    
- **Cobertura de pruebas** incrementada al ejecutar tests unitarios y de integración.

---

## 👨‍💻 Autor
Kevin Benjamin Sosa León
