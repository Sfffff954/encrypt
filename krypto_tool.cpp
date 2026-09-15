// krypto_tool.cpp
// -----------------------------------------------------------------------
// Datei-Verschlüsselungs-Tool mit GUI (C++ / GTK3 / OpenSSL)
//
// Verschlüsselt und entschlüsselt Dateien oder ganze Ordner (z.B. einen
// USB-Stick oder eine externe HDD) mit einem passwortbasierten
// AES-256-CBC-Schlüssel. Der Schlüssel wird per PBKDF2-HMAC-SHA256 mit
// zufälligem Salt aus dem Passwort abgeleitet.
//
// Kompilieren (Linux, Debian/Ubuntu):
//   sudo apt-get install libgtk-3-dev libssl-dev pkg-config g++
//   g++ krypto_tool.cpp -o krypto_tool `pkg-config --cflags --libs gtk+-3.0` -lssl -lcrypto -std=c++17
//
// Starten:
//   ./krypto_tool
// -----------------------------------------------------------------------

#include <gtk/gtk.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <thread>
#include <mutex>
#include <atomic>
#include <cstring>

namespace fs = std::filesystem;

static const char*  FILE_EXT        = ".enc";
static const int    SALT_SIZE       = 16;
static const int    IV_SIZE         = 16;
static const int    KEY_SIZE        = 32;      // AES-256
static const int    KDF_ITERATIONS  = 200000;  // PBKDF2 Iterationen

// ------------------------- Kryptografie ---------------------------------

struct CryptoError : public std::runtime_error {
    explicit CryptoError(const std::string& msg) : std::runtime_error(msg) {}
};

static std::vector<unsigned char> derive_key(const std::string& password,
                                              const unsigned char* salt) {
    std::vector<unsigned char> key(KEY_SIZE);
    if (PKCS5_PBKDF2_HMAC(password.c_str(), (int)password.size(),
                           salt, SALT_SIZE, KDF_ITERATIONS,
                           EVP_sha256(), KEY_SIZE, key.data()) != 1) {
        throw CryptoError("Schlüsselableitung (PBKDF2) fehlgeschlagen.");
    }
    return key;
}

// Verschlüsselt eine Datei: Ausgabe = SALT(16) || IV(16) || Ciphertext
static void encrypt_file(const fs::path& path, const std::string& password) {
    std::ifstream in(path, std::ios::binary);
    if (!in) throw CryptoError("Datei konnte nicht geoeffnet werden: " + path.string());
    std::vector<unsigned char> plaintext((std::istreambuf_iterator<char>(in)),
                                          std::istreambuf_iterator<char>());
    in.close();

    unsigned char salt[SALT_SIZE];
    unsigned char iv[IV_SIZE];
    if (RAND_bytes(salt, SALT_SIZE) != 1 || RAND_bytes(iv, IV_SIZE) != 1)
        throw CryptoError("Zufallszahlengenerator fehlgeschlagen.");

    auto key = derive_key(password, salt);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw CryptoError("EVP-Kontext konnte nicht erstellt werden.");

    std::vector<unsigned char> ciphertext(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
    int len = 0, total_len = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw CryptoError("Verschluesselung (Init) fehlgeschlagen.");
    }
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
                           plaintext.data(), (int)plaintext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw CryptoError("Verschluesselung (Update) fehlgeschlagen.");
    }
    total_len = len;
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw CryptoError("Verschluesselung (Final) fehlgeschlagen.");
    }
    total_len += len;
    EVP_CIPHER_CTX_free(ctx);

    fs::path out_path = path;
    out_path += FILE_EXT;
    std::ofstream out(out_path, std::ios::binary);
    if (!out) throw CryptoError("Ausgabedatei konnte nicht erstellt werden.");
    out.write(reinterpret_cast<char*>(salt), SALT_SIZE);
    out.write(reinterpret_cast<char*>(iv), IV_SIZE);
    out.write(reinterpret_cast<char*>(ciphertext.data()), total_len);
}

// Entschlüsselt eine zuvor mit encrypt_file erzeugte Datei.
static void decrypt_file(const fs::path& path, const std::string& password) {
    std::ifstream in(path, std::ios::binary);
    if (!in) throw CryptoError("Datei konnte nicht geoeffnet werden: " + path.string());
    std::vector<unsigned char> raw((std::istreambuf_iterator<char>(in)),
                                    std::istreambuf_iterator<char>());
    in.close();

    if (raw.size() < (size_t)(SALT_SIZE + IV_SIZE))
        throw CryptoError("Datei ist zu klein / kein gueltiges Format.");

    unsigned char salt[SALT_SIZE], iv[IV_SIZE];
    std::memcpy(salt, raw.data(), SALT_SIZE);
    std::memcpy(iv, raw.data() + SALT_SIZE, IV_SIZE);
    const unsigned char* ciphertext = raw.data() + SALT_SIZE + IV_SIZE;
    int ciphertext_len = (int)(raw.size() - SALT_SIZE - IV_SIZE);

    auto key = derive_key(password, salt);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw CryptoError("EVP-Kontext konnte nicht erstellt werden.");

    std::vector<unsigned char> plaintext(ciphertext_len + EVP_MAX_BLOCK_LENGTH);
    int len = 0, total_len = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw CryptoError("Entschluesselung (Init) fehlgeschlagen.");
    }
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext, ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw CryptoError("Entschluesselung (Update) fehlgeschlagen.");
    }
    total_len = len;
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        // Falsches Passwort oder beschaedigte Datei fuehrt hier zu einem Padding-Fehler
        throw CryptoError("Falsches Passwort oder beschaedigte Datei.");
    }
    total_len += len;
    EVP_CIPHER_CTX_free(ctx);

    fs::path out_path = path;
    std::string ext = path.extension().string();
    if (ext == FILE_EXT) {
        out_path = path;
        out_path.replace_extension("");
        // Falls die urspruengliche Datei selbst eine Endung hatte (z.B. foto.jpg.enc),
        // reicht replace_extension nicht - daher robusteren Ansatz nehmen:
        std::string s = path.string();
        if (s.size() > strlen(FILE_EXT) && s.substr(s.size() - strlen(FILE_EXT)) == FILE_EXT) {
            out_path = s.substr(0, s.size() - strlen(FILE_EXT));
        }
    } else {
        out_path = path.string() + ".dec";
    }

    std::ofstream out(out_path, std::ios::binary);
    if (!out) throw CryptoError("Ausgabedatei konnte nicht erstellt werden.");
    out.write(reinterpret_cast<char*>(plaintext.data()), total_len);
}

// Sammelt rekursiv alle Dateien aus einer Liste von Datei-/Ordnerpfaden.
static std::vector<fs::path> collect_files(const std::vector<std::string>& paths) {
    std::vector<fs::path> files;
    for (const auto& p : paths) {
        fs::path fp(p);
        if (fs::is_directory(fp)) {
            for (auto& entry : fs::recursive_directory_iterator(
                     fp, fs::directory_options::skip_permission_denied)) {
                if (entry.is_regular_file()) files.push_back(entry.path());
            }
        } else if (fs::is_regular_file(fp)) {
            files.push_back(fp);
        }
    }
    return files;
}

// Erkennt eingebundene USB-Sticks / externe Laufwerke unter Linux
// (klassischerweise unter /media/<user>/, /mnt/ oder /run/media/<user>/).
static std::vector<std::string> detect_removable_drives() {
    std::vector<std::string> drives;
    std::vector<fs::path> roots = {"/media", "/mnt", "/run/media"};
    for (auto& root : roots) {
        if (!fs::exists(root)) continue;
        for (auto& entry : fs::directory_iterator(root)) {
            if (!fs::is_directory(entry)) continue;
            // /media/<user>/<Laufwerk> hat noch eine Ebene mehr
            bool has_subdirs = false;
            for (auto& sub : fs::directory_iterator(entry.path())) {
                if (fs::is_directory(sub)) {
                    drives.push_back(sub.path().string());
                    has_subdirs = true;
                }
            }
            if (!has_subdirs) drives.push_back(entry.path().string());
        }
    }
    return drives;
}

// ------------------------- GUI -------------------------------------------

struct AppWidgets {
    GtkWidget* window;
    GtkWidget* list_box;       // GtkListBox mit ausgewaehlten Pfaden
    GtkWidget* password_entry;
    GtkWidget* show_pw_check;
    GtkWidget* delete_orig_check;
    GtkWidget* status_label;
    GtkWidget* progress_bar;

    std::vector<std::string> selected_paths;
    std::atomic<bool> job_running{false};
};

static void refresh_list(AppWidgets* app) {
    // Alte Eintraege entfernen
    GList* children = gtk_container_get_children(GTK_CONTAINER(app->list_box));
    for (GList* iter = children; iter != nullptr; iter = iter->next)
        gtk_widget_destroy(GTK_WIDGET(iter->data));
    g_list_free(children);

    for (auto& p : app->selected_paths) {
        GtkWidget* row = gtk_label_new(p.c_str());
        gtk_widget_set_halign(row, GTK_ALIGN_START);
        gtk_container_add(GTK_CONTAINER(app->list_box), row);
    }
    gtk_widget_show_all(app->list_box);
}

static void on_choose_files(GtkButton*, gpointer user_data) {
    auto* app = static_cast<AppWidgets*>(user_data);
    GtkWidget* dialog = gtk_file_chooser_dialog_new(
        "Dateien auswaehlen", GTK_WINDOW(app->window), GTK_FILE_CHOOSER_ACTION_OPEN,
        "_Abbrechen", GTK_RESPONSE_CANCEL, "_Oeffnen", GTK_RESPONSE_ACCEPT, nullptr);
    gtk_file_chooser_set_select_multiple(GTK_FILE_CHOOSER(dialog), TRUE);

    if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT) {
        GSList* files = gtk_file_chooser_get_filenames(GTK_FILE_CHOOSER(dialog));
        for (GSList* iter = files; iter != nullptr; iter = iter->next) {
            app->selected_paths.push_back(static_cast<char*>(iter->data));
            g_free(iter->data);
        }
        g_slist_free(files);
        refresh_list(app);
    }
    gtk_widget_destroy(dialog);
}

static void on_choose_folder(GtkButton*, gpointer user_data) {
    auto* app = static_cast<AppWidgets*>(user_data);
    GtkWidget* dialog = gtk_file_chooser_dialog_new(
        "Ordner / Laufwerk auswaehlen", GTK_WINDOW(app->window),
        GTK_FILE_CHOOSER_ACTION_SELECT_FOLDER,
        "_Abbrechen", GTK_RESPONSE_CANCEL, "_Waehlen", GTK_RESPONSE_ACCEPT, nullptr);

    if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT) {
        char* path = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));
        app->selected_paths.push_back(path);
        g_free(path);
        refresh_list(app);
    }
    gtk_widget_destroy(dialog);
}

static void on_clear_selection(GtkButton*, gpointer user_data) {
    auto* app = static_cast<AppWidgets*>(user_data);
    app->selected_paths.clear();
    refresh_list(app);
}

static void on_detect_drives(GtkButton*, gpointer user_data) {
    auto* app = static_cast<AppWidgets*>(user_data);
    auto drives = detect_removable_drives();

    if (drives.empty()) {
        GtkWidget* dialog = gtk_message_dialog_new(
            GTK_WINDOW(app->window), GTK_DIALOG_MODAL, GTK_MESSAGE_INFO, GTK_BUTTONS_OK,
            "Es wurden keine externen Laufwerke (USB-Stick/HDD) erkannt.\n"
            "Bitte stelle sicher, dass das Laufwerk eingebunden (gemountet) ist,\n"
            "oder waehle den Ordner manuell aus.");
        gtk_dialog_run(GTK_DIALOG(dialog));
        gtk_widget_destroy(dialog);
        return;
    }

    GtkWidget* dialog = gtk_dialog_new_with_buttons(
        "Erkannte Laufwerke", GTK_WINDOW(app->window), GTK_DIALOG_MODAL,
        "_Abbrechen", GTK_RESPONSE_CANCEL, "_Hinzufuegen", GTK_RESPONSE_ACCEPT, nullptr);
    gtk_window_set_default_size(GTK_WINDOW(dialog), 420, 240);

    GtkWidget* content = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
    GtkWidget* scroll = gtk_scrolled_window_new(nullptr, nullptr);
    gtk_widget_set_vexpand(scroll, TRUE);
    GtkWidget* listbox = gtk_list_box_new();
    gtk_list_box_set_selection_mode(GTK_LIST_BOX(listbox), GTK_SELECTION_MULTIPLE);

    for (auto& d : drives) {
        GtkWidget* row = gtk_label_new(d.c_str());
        gtk_widget_set_halign(row, GTK_ALIGN_START);
        gtk_widget_set_margin_start(row, 6);
        gtk_widget_set_margin_top(row, 4);
        gtk_widget_set_margin_bottom(row, 4);
        gtk_list_box_insert(GTK_LIST_BOX(listbox), row, -1);
    }
    gtk_container_add(GTK_CONTAINER(scroll), listbox);
    gtk_container_add(GTK_CONTAINER(content), scroll);
    gtk_widget_show_all(dialog);

    if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT) {
        GList* selected = gtk_list_box_get_selected_rows(GTK_LIST_BOX(listbox));
        for (GList* iter = selected; iter != nullptr; iter = iter->next) {
            int idx = gtk_list_box_row_get_index(GTK_LIST_BOX_ROW(iter->data));
            if (idx >= 0 && idx < (int)drives.size())
                app->selected_paths.push_back(drives[idx]);
        }
        g_list_free(selected);
        refresh_list(app);
    }
    gtk_widget_destroy(dialog);
}

static void on_toggle_show_password(GtkToggleButton* btn, gpointer user_data) {
    auto* app = static_cast<AppWidgets*>(user_data);
    gtk_entry_set_visibility(GTK_ENTRY(app->password_entry),
                              gtk_toggle_button_get_active(btn));
}

struct JobResult {
    int ok = 0;
    std::vector<std::string> errors;
    bool is_encrypt = true;
};

static gboolean job_done_idle(gpointer data) {
    auto* result = static_cast<JobResult*>(data);
    std::ostringstream msg;
    msg << result->ok << " Datei(en) erfolgreich "
        << (result->is_encrypt ? "verschluesselt." : "entschluesselt.");
    if (!result->errors.empty()) {
        msg << "\n\n" << result->errors.size() << " Fehler:\n";
        int shown = 0;
        for (auto& e : result->errors) {
            if (shown++ >= 10) break;
            msg << e << "\n";
        }
    }
    delete result;
    return G_SOURCE_REMOVE; // Platzhalter, echte Anzeige erfolgt via app-Zeiger unten
}

// Wir brauchen Zugriff auf 'app' im idle-Callback -> Wrapper-Struktur
struct IdlePayload {
    AppWidgets* app;
    JobResult* result;
};

static gboolean job_done_idle2(gpointer data) {
    auto* payload = static_cast<IdlePayload*>(data);
    AppWidgets* app = payload->app;
    JobResult* result = payload->result;

    std::ostringstream msg;
    msg << result->ok << " Datei(en) erfolgreich "
        << (result->is_encrypt ? "verschluesselt." : "entschluesselt.");

    GtkMessageType type = GTK_MESSAGE_INFO;
    if (!result->errors.empty()) {
        type = GTK_MESSAGE_WARNING;
        msg << "\n\n" << result->errors.size() << " Fehler:\n";
        int shown = 0;
        for (auto& e : result->errors) {
            if (shown++ >= 10) break;
            msg << e << "\n";
        }
    }

    GtkWidget* dialog = gtk_message_dialog_new(
        GTK_WINDOW(app->window), GTK_DIALOG_MODAL, type, GTK_BUTTONS_OK, "%s", msg.str().c_str());
    gtk_dialog_run(GTK_DIALOG(dialog));
    gtk_widget_destroy(dialog);

    gtk_label_set_text(GTK_LABEL(app->status_label), "Fertig.");
    gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(app->progress_bar), 0.0);
    app->job_running = false;

    delete result;
    delete payload;
    return G_SOURCE_REMOVE;
}

struct ProgressPayload {
    AppWidgets* app;
    double fraction;
    std::string text;
};

static gboolean progress_update_idle(gpointer data) {
    auto* p = static_cast<ProgressPayload*>(data);
    gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(p->app->progress_bar), p->fraction);
    gtk_label_set_text(GTK_LABEL(p->app->status_label), p->text.c_str());
    delete p;
    return G_SOURCE_REMOVE;
}

static void run_job(AppWidgets* app, bool encrypt_mode) {
    if (app->selected_paths.empty()) {
        GtkWidget* dialog = gtk_message_dialog_new(
            GTK_WINDOW(app->window), GTK_DIALOG_MODAL, GTK_MESSAGE_WARNING, GTK_BUTTONS_OK,
            "Bitte zuerst Dateien oder einen Ordner auswaehlen.");
        gtk_dialog_run(GTK_DIALOG(dialog));
        gtk_widget_destroy(dialog);
        return;
    }
    std::string password = gtk_entry_get_text(GTK_ENTRY(app->password_entry));
    if (password.empty()) {
        GtkWidget* dialog = gtk_message_dialog_new(
            GTK_WINDOW(app->window), GTK_DIALOG_MODAL, GTK_MESSAGE_WARNING, GTK_BUTTONS_OK,
            "Bitte ein Passwort eingeben.");
        gtk_dialog_run(GTK_DIALOG(dialog));
        gtk_widget_destroy(dialog);
        return;
    }
    if (app->job_running) return;
    app->job_running = true;

    bool delete_original = gtk_toggle_button_get_active(
        GTK_TOGGLE_BUTTON(app->delete_orig_check));
    std::vector<std::string> paths = app->selected_paths;

    std::thread([app, password, encrypt_mode, delete_original, paths]() {
        auto files = collect_files(paths);
        auto* result = new JobResult();
        result->is_encrypt = encrypt_mode;

        size_t total = files.size();
        for (size_t i = 0; i < total; ++i) {
            const fs::path& f = files[i];
            try {
                if (encrypt_mode) {
                    if (f.extension() == FILE_EXT) continue;
                    encrypt_file(f, password);
                } else {
                    if (f.extension() != FILE_EXT) continue;
                    decrypt_file(f, password);
                }
                if (delete_original) fs::remove(f);
                result->ok++;
            } catch (const std::exception& e) {
                result->errors.push_back(f.filename().string() + ": " + e.what());
            }

            auto* pp = new ProgressPayload{app, (double)(i + 1) / (double)total,
                                            "Verarbeitet (" + std::to_string(i + 1) + "/" +
                                                std::to_string(total) + "): " +
                                                f.filename().string()};
            g_idle_add(progress_update_idle, pp);
        }

        auto* payload = new IdlePayload{app, result};
        g_idle_add(job_done_idle2, payload);
    }).detach();
}

static void on_encrypt(GtkButton*, gpointer user_data) {
    run_job(static_cast<AppWidgets*>(user_data), true);
}
static void on_decrypt(GtkButton*, gpointer user_data) {
    run_job(static_cast<AppWidgets*>(user_data), false);
}

static void apply_css(GtkWidget* window) {
    GtkCssProvider* provider = gtk_css_provider_new();
    const char* css =
        "window { background-color: #1e1e2e; }"
        "label { color: #e0e0f0; }"
        "entry { padding: 4px; }"
        "button.suggested-action { background-image: none; background-color: #7aa2f7; color: #101018; }";
    gtk_css_provider_load_from_data(provider, css, -1, nullptr);
    gtk_style_context_add_provider_for_screen(
        gdk_screen_get_default(), GTK_STYLE_PROVIDER(provider),
        GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    g_object_unref(provider);
}

int main(int argc, char** argv) {
    gtk_init(&argc, &argv);

    auto* app = new AppWidgets();
    app->window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(app->window), "Datei-Verschluesselung - HDD & USB Schutz");
    gtk_window_set_default_size(GTK_WINDOW(app->window), 640, 500);
    g_signal_connect(app->window, "destroy", G_CALLBACK(gtk_main_quit), nullptr);
    apply_css(app->window);

    GtkWidget* vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_container_set_border_width(GTK_CONTAINER(vbox), 16);
    gtk_container_add(GTK_CONTAINER(app->window), vbox);

    GtkWidget* title = gtk_label_new(nullptr);
    gtk_label_set_markup(GTK_LABEL(title),
        "<span size='large' weight='bold' foreground='#7aa2f7'>"
        "\xF0\x9F\x94\x92 Datei- &amp; USB-/HDD-Verschluesselung</span>");
    gtk_widget_set_halign(title, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(vbox), title, FALSE, FALSE, 0);

    GtkWidget* subtitle = gtk_label_new(
        "Waehle Dateien oder einen Ordner (z.B. dein USB-Laufwerk) aus,\n"
        "vergib ein Passwort und verschluessle oder entschluessle deine Daten.");
    gtk_widget_set_halign(subtitle, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(vbox), subtitle, FALSE, FALSE, 0);

    // Buttons: Auswahl
    GtkWidget* btn_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget* btn_files = gtk_button_new_with_label("\xF0\x9F\x93\x84 Dateien waehlen...");
    GtkWidget* btn_folder = gtk_button_new_with_label("\xF0\x9F\x93\x81 Ordner waehlen...");
    GtkWidget* btn_detect = gtk_button_new_with_label("\xF0\x9F\x94\x8C USB/HDD erkennen");
    GtkWidget* btn_clear = gtk_button_new_with_label("\xE2\x9C\x96 Auswahl leeren");
    gtk_box_pack_start(GTK_BOX(btn_box), btn_files, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(btn_box), btn_folder, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(btn_box), btn_detect, FALSE, FALSE, 0);
    gtk_box_pack_end(GTK_BOX(btn_box), btn_clear, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), btn_box, FALSE, FALSE, 0);

    // Liste ausgewaehlter Pfade
    GtkWidget* scroll = gtk_scrolled_window_new(nullptr, nullptr);
    gtk_widget_set_vexpand(scroll, TRUE);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
                                    GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    app->list_box = gtk_list_box_new();
    gtk_container_add(GTK_CONTAINER(scroll), app->list_box);
    gtk_box_pack_start(GTK_BOX(vbox), scroll, TRUE, TRUE, 0);

    // Passwort
    GtkWidget* pw_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget* pw_label = gtk_label_new("Passwort:");
    app->password_entry = gtk_entry_new();
    gtk_entry_set_visibility(GTK_ENTRY(app->password_entry), FALSE);
    app->show_pw_check = gtk_check_button_new_with_label("anzeigen");
    g_signal_connect(app->show_pw_check, "toggled", G_CALLBACK(on_toggle_show_password), app);
    gtk_box_pack_start(GTK_BOX(pw_box), pw_label, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(pw_box), app->password_entry, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(pw_box), app->show_pw_check, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), pw_box, FALSE, FALSE, 0);

    app->delete_orig_check = gtk_check_button_new_with_label(
        "Originaldatei nach Vorgang loeschen");
    gtk_box_pack_start(GTK_BOX(vbox), app->delete_orig_check, FALSE, FALSE, 0);

    // Aktionen
    GtkWidget* action_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget* btn_encrypt = gtk_button_new_with_label("\xF0\x9F\x94\x90 Verschluesseln");
    GtkStyleContext* ctx = gtk_widget_get_style_context(btn_encrypt);
    gtk_style_context_add_class(ctx, "suggested-action");
    GtkWidget* btn_decrypt = gtk_button_new_with_label("\xF0\x9F\x94\x93 Entschluesseln");
    gtk_box_pack_start(GTK_BOX(action_box), btn_encrypt, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(action_box), btn_decrypt, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), action_box, FALSE, FALSE, 0);

    // Status + Fortschritt
    app->status_label = gtk_label_new("Bereit.");
    gtk_widget_set_halign(app->status_label, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(vbox), app->status_label, FALSE, FALSE, 0);

    app->progress_bar = gtk_progress_bar_new();
    gtk_box_pack_start(GTK_BOX(vbox), app->progress_bar, FALSE, FALSE, 0);

    // Signale verbinden
    g_signal_connect(btn_files, "clicked", G_CALLBACK(on_choose_files), app);
    g_signal_connect(btn_folder, "clicked", G_CALLBACK(on_choose_folder), app);
    g_signal_connect(btn_detect, "clicked", G_CALLBACK(on_detect_drives), app);
    g_signal_connect(btn_clear, "clicked", G_CALLBACK(on_clear_selection), app);
    g_signal_connect(btn_encrypt, "clicked", G_CALLBACK(on_encrypt), app);
    g_signal_connect(btn_decrypt, "clicked", G_CALLBACK(on_decrypt), app);

    gtk_widget_show_all(app->window);
    gtk_main();

    delete app;
    return 0;
}
