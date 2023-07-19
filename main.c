#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mysql/mysql.h>

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

    //ハッシュ化
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, password, strlen(password));
    SHA256_Final(digest, &sha256);

    //ハッシュ値を16進数に変換
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(&hash[i * 2], "%02x", digest[i]);
    }
}

int main(void) {
    MYSQL *conn;
    MYSQL_RES *res;
    MYSQL_ROW row;
    Profile dbProfile;
    char inputUsername[PASSWORD_LENGTH];
    char inputPassword[PASSWORD_LENGTH];
    char passwordHash[PASSWORD_LENGTH];

    //データベース接続の確立
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

    //ユーザーからの入力を受け取る
    printf("Enter your username: ");
    scanf("%s", inputUsername);

    printf("\n");

    printf("Enter your password: ");
    scanf("%s", inputPassword);

    printf("\n");
  
    //パスワードのハッシュ化
    calculatePasswordHash(inputPassword, passwordHash);

    //データベースからプロファイル情報を取得
    char query[256];
    sprintf(query, "SELECT * FROM profiles WHERE username = '%s' AND password_hash = '%s'", inputUsername, passwordHash); //SQL意味わかんないよ　SQL触れるやつすげぇ
    if (mysql_query(conn, query) != 0) {
        fprintf(stderr, "mysql_query failed: %s\n", mysql_error(conn));
        mysql_close(conn);
        return 1;
    }

    res = mysql_use_result(conn);
    if (res == NULL) {
        fprintf(stderr, "mysql_use_result failed\n");
        mysql_close(conn);
        return 1;
    }

    if ((row = mysql_fetch_row(res)) != NULL) {
        //プロファイル情報を取得
        strcpy(dbProfile.username, row[0]);
        strcpy(dbProfile.passwordHash, row[1]);
        strcpy(dbProfile.birthday, row[2]);
        strcpy(dbProfile.message, row[3]);

        printf("\n----- Profile -----\n");
        printf("Username: %s\n", dbProfile.username);
        printf("Birthday: %s\n", dbProfile.birthday);
        printf("Message: %s\n", dbProfile.message);
    } else {
        printf("Invalid username or password\n");
    }

    //データベース接続のクローズ
    mysql_free_result(res);
    mysql_close(conn);

    return 0;
}
