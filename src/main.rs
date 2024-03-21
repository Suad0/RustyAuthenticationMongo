use actix_web::{App, HttpResponse, HttpServer, Responder, web};
use bson::{doc, Document};
use mongodb::{Client, Collection, Database};
use serde::{Deserialize, Serialize};


const MONGODB_URL: &str = "mongodb://localhost:27017";
const DATABASE_NAME: &str = "rusty_users";
const COLLECTION_NAME: &str = "users";

#[derive(Debug, Deserialize, Serialize)]
struct User {
    username: String,
    password: String,
}

impl User {
    fn new(username: String, password: String) -> Self {
        let password_hash = bcrypt::hash(password, bcrypt::DEFAULT_COST).unwrap(); // Hash password
        User { username, password: password_hash }
    }

    fn verify_password(&self, password: &str) -> bool {
        bcrypt::verify(password, &self.password).unwrap_or(false) // Verify hashed password
    }
}


async fn register(user: web::Json<User>) -> impl Responder {
    let hashed_password = bcrypt::hash(&user.password, bcrypt::DEFAULT_COST).unwrap();
    let user = User {
        username: user.username.clone(),
        password: hashed_password,
    };

    let client = Client::with_uri_str(MONGODB_URL).await.unwrap();
    let db: Database = client.database(DATABASE_NAME);
    let collection: Collection<Document> = db.collection(COLLECTION_NAME);

    let user_document = bson::to_document(&user).unwrap();

    match collection.insert_one(user_document, None).await {
        Ok(_) => HttpResponse::Created().json(user),
        Err(_) => HttpResponse::InternalServerError().body("Failed to register user"),
    }
}




async fn login(user: web::Json<User>) -> impl Responder {
    let client = Client::with_uri_str(MONGODB_URL).await.unwrap();
    let db: Database = client.database(DATABASE_NAME);
    let collection: Collection<Document> = db.collection(COLLECTION_NAME);

    let filter = doc! { "username": &user.username };

    match collection.find_one(filter, None).await {
        Ok(Some(document)) => {
            let stored_user: User = bson::from_document(document).unwrap();
            if stored_user.verify_password(&user.password) {
                HttpResponse::Ok().body("Login successful")
            } else {
                HttpResponse::Unauthorized().body("Invalid username or password")
            }
        }
        Ok(None) => HttpResponse::Unauthorized().body("Invalid username or password"),
        Err(_) => HttpResponse::InternalServerError().body("Failed to login"),
    }
}


#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .route("/register", web::post().to(register))
            .route("/login", web::post().to(login))
    })
        .bind("127.0.0.1:8080")?
        .run()
        .await
}

/*
curl -X POST \
  http://127.0.0.1:8080/register \
  -H 'Content-Type: application/json' \
  -d '{
    "username": "test_hash",
    "password": "password"
}'

curl -X POST \
  http://127.0.0.1:8080/login \
  -H 'Content-Type: application/json' \
  -d '{
    "username": "test_hash",
    "password": "password"
}'


 */