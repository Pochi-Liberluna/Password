#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mysql/mysql.h>
#include <openssl/sha.h>

#define PASSWORD_LENGTH 64
#define DB_HOST "localhost"
#define DB_USER "username"
#define DB_PASSWORD "password"
#define DB_NAME "database_name"

typedef struct {
    char username[PASSWORD_LENGTH];
    char passwordHash[PASSWORD_LENGTH];
    char birthday[100];
    char message[100];
} Profile;

void calculatePasswordHash(const char *password, char *hash) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, password, strlen(password));
    SHA256_Final(digest, &sha256);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(&hash[i * 2], "%02x", digest[i]);
    }
}

void registerNewUser(MYSQL *conn) {
    char inputUsername[PASSWORD_LENGTH];
    char inputPassword[PASSWORD_LENGTH];
    char passwordHash[PASSWORD_LENGTH];
    char inputBirthday[100];
    char inputMessage[100];

    printf("Enter a new username: ");
    scanf("%s", inputUsername);

    printf("\n");

    printf("Enter a new password: ");
    scanf("%s", inputPassword);

    printf("\n");

    printf("Enter your birthday: ");
    scanf("%s", inputBirthday);

    printf("\n");

    printf("Enter a message: ");
    scanf("%s", inputMessage);

    printf("\n");

    //パスワードのハッシュ化
    calculatePasswordHash(inputPassword, passwordHash);

    //データベースに新しいユーザー情報を挿入(プリペアドステートメントってやつ使ってSQLi対策済)
    MYSQL_STMT *stmt;
    char query[256];
    sprintf(query, "INSERT INTO profiles (username, password_hash, birthday, message) VALUES (?, ?, ?, ?)");

    stmt = mysql_stmt_init(conn);
    if (mysql_stmt_prepare(stmt, query, strlen(query)) != 0) {
        fprintf(stderr, "mysql_stmt_prepare failed: %s\n", mysql_stmt_error(stmt));
        return;
    }

    MYSQL_BIND bind[4];
    memset(bind, 0, sizeof(bind));
    bind[0].buffer_type = MYSQL_TYPE_STRING;
    bind[0].buffer = inputUsername;
    bind[0].buffer_length = strlen(inputUsername);
    bind[1].buffer_type = MYSQL_TYPE_STRING;
    bind[1].buffer = passwordHash;
    bind[1].buffer_length = strlen(passwordHash);
    bind[2].buffer_type = MYSQL_TYPE_STRING;
    bind[2].buffer = inputBirthday;
    bind[2].buffer_length = strlen(inputBirthday);
    bind[3].buffer_type = MYSQL_TYPE_STRING;
    bind[3].buffer = inputMessage;
    bind[3].buffer_length = strlen(inputMessage);

    if (mysql_stmt_bind_param(stmt, bind) != 0) {
        fprintf(stderr, "mysql_stmt_bind_param failed: %s\n", mysql_stmt_error(stmt));
        return;
    }

    if (mysql_stmt_execute(stmt) != 0) {
        fprintf(stderr, "mysql_stmt_execute failed: %s\n", mysql_stmt_error(stmt));
        return;
    }

    printf("New user registered successfully!\n");

    mysql_stmt_close(stmt);
}

int main(void) {
    MYSQL *conn;
    MYSQL_RES *res;
    MYSQL_ROW row;
    Profile dbProfile;
    char inputUsername[PASSWORD_LENGTH];
    char inputPassword[PASSWORD_LENGTH];
    char passwordHash[PASSWORD_LENGTH];

    //データベース接続
    conn = mysql_init(NULL);
    if (conn == NULL) {
        fprintf(stderr, "mysql_init failed\n");
        return 1;
    }

    if (mysql_real_connect(conn, DB_HOST, DB_USER, DB_PASSWORD, DB_NAME, 0, NULL, 0) == NULL) {
        fprintf(stderr, "mysql_real_connect failed: %s\n", mysql_error(conn));
        mysql_close(conn);
        return 1;
    }

    int option;
    printf("Choose an option:\n");
    printf("1. Register new user\n");
    printf("2. Login\n");
    printf("Option: ");
    scanf("%d", &option);

    if (option == 1) {
        //新規登録
        registerNewUser(conn);
    } else if (option == 2) {
        //ログイン
        printf("Enter your username: ");
        scanf("%s", inputUsername);
        printf("\n");

        printf("Enter your password: ");
        scanf("%s", inputPassword);
        printf("\n");

        calculatePasswordHash(inputPassword, passwordHash);

        char query[256];
        sprintf(query, "SELECT * FROM profiles WHERE username = ? AND password_hash = ?");            //SQL意味わかんないよ　SQLわかるやつすげぇ
        MYSQL_STMT *stmt;
        stmt = mysql_stmt_init(conn);
        if (mysql_stmt_prepare(stmt, query, strlen(query)) != 0) {
            fprintf(stderr, "mysql_stmt_prepare failed: %s\n", mysql_stmt_error(stmt));
            mysql_close(conn);
            return 1;
        }

        MYSQL_BIND bind[2];
        memset(bind, 0, sizeof(bind));
        bind[0].buffer_type = MYSQL_TYPE_STRING;
        bind[0].buffer = inputUsername;
        bind[0].buffer_length = strlen(inputUsername);
        bind[1].buffer_type = MYSQL_TYPE_STRING;
        bind[1].buffer = passwordHash;
        bind[1].buffer_length = strlen(passwordHash);

        if (mysql_stmt_bind_param(stmt, bind) != 0) {
            fprintf(stderr, "mysql_stmt_bind_param failed: %s\n", mysql_stmt_error(stmt));
            mysql_close(conn);
            return 1;
        }

        if (mysql_stmt_execute(stmt) != 0) {
            fprintf(stderr, "mysql_stmt_execute failed: %s\n", mysql_stmt_error(stmt));
            mysql_stmt_close(stmt);
            mysql_close(conn);
            return 1;
        }

        res = mysql_stmt_result_metadata(stmt);
        if (res == NULL) {
            fprintf(stderr, "mysql_stmt_result_metadata failed\n");
            mysql_stmt_close(stmt);
            mysql_close(conn);
            return 1;
        }

        int num_fields = mysql_num_fields(res);
        MYSQL_BIND result_bind[num_fields];
        memset(result_bind, 0, sizeof(result_bind));
        char username[PASSWORD_LENGTH];
        char birthday[100];
        char message[100];
        result_bind[0].buffer_type = MYSQL_TYPE_STRING;
        result_bind[0].buffer = username;
        result_bind[0].buffer_length = sizeof(username) - 1; // null-terminated string
        result_bind[1].buffer_type = MYSQL_TYPE_STRING;
        result_bind[1].buffer = passwordHash;
        result_bind[1].buffer_length = sizeof(passwordHash) - 1; // null-terminated string
        result_bind[2].buffer_type = MYSQL_TYPE_STRING;
        result_bind[2].buffer = birthday;
        result_bind[2].buffer_length = sizeof(birthday) - 1; // null-terminated string
        result_bind[3].buffer_type = MYSQL_TYPE_STRING;
        result_bind[3].buffer = message;
        result_bind[3].buffer_length = sizeof(message) - 1; // null-terminated string

        if (mysql_stmt_bind_result(stmt, result_bind) != 0) {
            fprintf(stderr, "mysql_stmt_bind_result failed: %s\n", mysql_stmt_error(stmt));
            mysql_free_result(res);
            mysql_stmt_close(stmt);
            mysql_close(conn);
            return 1;
        }

        if (mysql_stmt_fetch(stmt) == MYSQL_NO_DATA) {
            printf("Invalid username or password\n");
        } else {
            printf("\n----- Profile -----\n");
            printf("Username: %s\n", username);
            printf("Birthday: %s\n", birthday);
            printf("Message: %s\n", message);
        }

        mysql_free_result(res);
        mysql_stmt_close(stmt);
    } else {
        printf("Invalid option.\n");
    }

    mysql_close(conn);
    return 0;
}
