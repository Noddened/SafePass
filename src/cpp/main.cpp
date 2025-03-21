#include <sqlite3.h>
#include <iostream>
#include <string>
#include <sodium.h>

class PasswordDatabase {
private:
    sqlite3* db;
    std::string current_user_table;

    void execute(const std::string& sql) {
        char* errMsg = nullptr;
        if (sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &errMsg) != SQLITE_OK) {
            std::string error = "SQL error: " + std::string(errMsg);
            sqlite3_free(errMsg);
            throw std::runtime_error(error);
        }
    }

    bool tableExists(const std::string& tableName) {
        std::string sql = "SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?";
        sqlite3_stmt* stmt;
        bool exists = false;

        if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, tableName.c_str(), -1, SQLITE_STATIC);
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                exists = (sqlite3_column_int(stmt, 0) == 1);
            }
            sqlite3_finalize(stmt);
        }
        return exists;
    }

public:
    PasswordDatabase(const std::string& db_name) : db(nullptr), current_user_table("") {
        if (sodium_init() < 0) {
            throw std::runtime_error("Failed to initialize libsodium");
        }

        if (sqlite3_open(db_name.c_str(), &db) != SQLITE_OK) {
            throw std::runtime_error("Failed to open database");
        }

        if (!tableExists("users")) {
            execute("CREATE TABLE users ("
                    "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                    "username TEXT UNIQUE, "
                    "master_password_hash TEXT)");
        }
    }

    ~PasswordDatabase() {
        if (db) sqlite3_close(db);
    }

    void registerUser(const std::string& username, const std::string& password) {

        std::string check_sql = "SELECT username FROM users WHERE username = ?";
        sqlite3_stmt* check_stmt;

        if (sqlite3_prepare_v2(db, check_sql.c_str(), -1, &check_stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_text(check_stmt, 1, username.c_str(), -1, SQLITE_STATIC);

            if (sqlite3_step(check_stmt) == SQLITE_ROW) {
                sqlite3_finalize(check_stmt);
                throw std::runtime_error("Username already exists");
            }
            sqlite3_finalize(check_stmt);
        }

        // Хэшируем пароль
        char hashed_password[crypto_pwhash_STRBYTES];
        if (crypto_pwhash_str(hashed_password,
                              password.c_str(),
                              password.length(),
                              crypto_pwhash_OPSLIMIT_SENSITIVE,
                              crypto_pwhash_MEMLIMIT_SENSITIVE) != 0) {
            throw std::runtime_error("Password hashing failed");
        }


        std::string insert_sql = "INSERT INTO users (username, master_password_hash) VALUES (?, ?)";
        sqlite3_stmt* insert_stmt;

        if (sqlite3_prepare_v2(db, insert_sql.c_str(), -1, &insert_stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_text(insert_stmt, 1, username.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(insert_stmt, 2, hashed_password, -1, SQLITE_STATIC);

            if (sqlite3_step(insert_stmt) != SQLITE_DONE) {
                sqlite3_finalize(insert_stmt);
                throw std::runtime_error("Registration failed");
            }
            sqlite3_finalize(insert_stmt);
        }

        // я победил, пиво мое мухмахахахахахахахахах
        std::string user_table = username + "_passwords";
        execute("CREATE TABLE IF NOT EXISTS " + user_table + " ("
                                                             "service_name TEXT PRIMARY KEY, "
                                                             "password TEXT, "
                                                             "description TEXT)");
    }

    bool authenticate(const std::string& username, const std::string& master_password) {
        std::string sql = "SELECT master_password_hash FROM users WHERE username = ?";
        sqlite3_stmt* stmt;
        bool auth = false;

        if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);

            if (sqlite3_step(stmt) == SQLITE_ROW) {
                const char* stored_hash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
                if (crypto_pwhash_str_verify(stored_hash,
                                             master_password.c_str(),
                                             master_password.length()) == 0) {
                    current_user_table = username + "_passwords";
                    auth = true;
                }
            }
            sqlite3_finalize(stmt);
        }

        if (!auth) throw std::runtime_error("Invalid credentials");
        return true;
    }

    void addPassword(const std::string& service, const std::string& password, const std::string& description) {
        if (current_user_table.empty()) {
            throw std::runtime_error("Not authenticated");
        }

        std::string sql = "INSERT INTO " + current_user_table +
                          " (service_name, password, description) VALUES (?, ?, ?)";
        sqlite3_stmt* stmt;

        if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, service.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 2, password.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 3, description.c_str(), -1, SQLITE_STATIC);

            if (sqlite3_step(stmt) != SQLITE_DONE) {
                sqlite3_finalize(stmt);
                throw std::runtime_error("Failed to add password");
            }
            sqlite3_finalize(stmt);
        }
    }

    void listPasswords() {
        if (current_user_table.empty()) {
            throw std::runtime_error("Not authenticated");
        }

        std::string sql = "SELECT * FROM " + current_user_table;
        sqlite3_stmt* stmt;

        if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
            std::cout << "\nStored passwords:\n";
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                std::cout << "Service: " << sqlite3_column_text(stmt, 0)
                << "\nPassword: " << sqlite3_column_text(stmt, 1)
                << "\nDescription: " << sqlite3_column_text(stmt, 2)
                << "\n\n";
            }
            sqlite3_finalize(stmt);
        }
    }
};

// Пример использования
int main() {
        PasswordDatabase manager("passwords.db");


        //manager.registerUser("roman", "Haha_Roma_Pivo_moe");


        if (manager.authenticate("roman", "Haha_Roma_Pivo_moe")) {

            manager.addPassword("SKF_MTUCI", "PIVO_IZ_KVADRUPELYA", "ya zhe govorol, chto realizuyu");


            manager.listPasswords();
        }
    return 0;
}
