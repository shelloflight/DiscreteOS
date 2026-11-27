//! Localization (`en-US`, `en-GB`, `de-DE`, `fr-FR`, `es-ES`), multi-layout keyboard metadata &
//! verification tables (`us`, `uk`, `de`, `fr`, `es`), and timezone offset parsing (`dosid::locale`).
//!
//! Pure `no_std`, `#![forbid(unsafe_code)]`, zero external crates.

use crate::oobe::{KEYBOARDS, LANGUAGES, TIMEZONES};

/// Supported UI display languages.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum Language {
    #[default]
    EnUs = 0,
    EnGb = 1,
    DeDe = 2,
    FrFr = 3,
    EsEs = 4,
}

impl Language {
    pub const ALL: [Self; 5] = [Self::EnUs, Self::EnGb, Self::DeDe, Self::FrFr, Self::EsEs];

    pub fn from_code(code: &str) -> Self {
        match code {
            "en-GB" | "en_GB" => Self::EnGb,
            "de-DE" | "de_DE" | "de" => Self::DeDe,
            "fr-FR" | "fr_FR" | "fr" => Self::FrFr,
            "es-ES" | "es_ES" | "es" => Self::EsEs,
            _ => Self::EnUs,
        }
    }

    pub const fn from_id(id: u8) -> Self {
        match id {
            1 => Self::EnGb,
            2 => Self::DeDe,
            3 => Self::FrFr,
            4 => Self::EsEs,
            _ => Self::EnUs,
        }
    }

    pub const fn id(self) -> u8 {
        self as u8
    }

    pub const fn code(self) -> &'static str {
        LANGUAGES[self as usize].0
    }

    pub const fn name(self) -> &'static str {
        LANGUAGES[self as usize].1
    }

    /// Suggested default keyboard layout for this language.
    pub const fn default_keyboard(self) -> KeyboardLayout {
        match self {
            Self::EnUs => KeyboardLayout::Us,
            Self::EnGb => KeyboardLayout::Uk,
            Self::DeDe => KeyboardLayout::De,
            Self::FrFr => KeyboardLayout::Fr,
            Self::EsEs => KeyboardLayout::Es,
        }
    }
}

/// Supported hardware keyboard layouts (PC scancode Set 1 / Linux input keycodes).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum KeyboardLayout {
    #[default]
    Us = 0,
    Uk = 1,
    De = 2,
    Fr = 3,
    Es = 4,
}

impl KeyboardLayout {
    pub const ALL: [Self; 5] = [Self::Us, Self::Uk, Self::De, Self::Fr, Self::Es];

    pub fn from_code(code: &str) -> Self {
        match code {
            "uk" | "gb" | "en-GB" => Self::Uk,
            "de" | "de-DE" => Self::De,
            "fr" | "fr-FR" => Self::Fr,
            "es" | "es-ES" => Self::Es,
            _ => Self::Us,
        }
    }

    pub const fn from_id(id: u8) -> Self {
        match id {
            1 => Self::Uk,
            2 => Self::De,
            3 => Self::Fr,
            4 => Self::Es,
            _ => Self::Us,
        }
    }

    pub const fn id(self) -> u8 {
        self as u8
    }

    pub const fn code(self) -> &'static str {
        KEYBOARDS[self as usize].0
    }

    pub const fn name(self) -> &'static str {
        KEYBOARDS[self as usize].1
    }

    pub const fn sample_hint(self) -> &'static str {
        match self {
            Self::Us => "QWERTY: Shift+2=@, Shift+3=#, Y/Z standard",
            Self::Uk => "UK QWERTY: Shift+2=\", Shift+3=£, Shift+'=@",
            Self::De => "German QWERTZ: Y/Z swapped, Ü Ö Ä ß, AltGr+Q=@",
            Self::Fr => "French AZERTY: A/Q Z/W swapped, é è ç à, Shift+1..0=digits",
            Self::Es => "Spanish QWERTY: Ñ next to L, ¡ ¿, AltGr+2=@",
        }
    }
}

/// Parse a timezone label (`"UTC"`, `"UTC-8"`, `"UTC+1"`, `"UTC+5:30"`, etc.) into a signed
/// offset in minutes from UTC. Unknown strings fail safely to `0` (UTC).
pub fn timezone_offset_minutes(tz: &str) -> i32 {
    let t = tz.trim();
    if t.eq_ignore_ascii_case("UTC") {
        return 0;
    }
    let Some(rest) = t.strip_prefix("UTC").or_else(|| t.strip_prefix("utc")) else {
        return 0;
    };
    let (sign, digits) = if let Some(d) = rest.strip_prefix('+') {
        (1i32, d)
    } else if let Some(d) = rest.strip_prefix('-') {
        (-1i32, d)
    } else {
        return 0;
    };
    let (h_str, m_str) = digits.split_once(':').unwrap_or((digits, "0"));
    let Ok(h) = h_str.parse::<i32>() else { return 0 };
    let Ok(m) = m_str.parse::<i32>() else { return 0 };
    if !(0..=14).contains(&h) || !(0..=59).contains(&m) {
        return 0;
    }
    sign * (h * 60 + m)
}

/// Validate a timezone identifier against supported entries or valid `UTC±H` format.
pub fn is_valid_timezone(tz: &str) -> bool {
    TIMEZONES.iter().any(|(code, _)| *code == tz)
        || tz == "UTC"
        || ((tz.starts_with("UTC+") || tz.starts_with("UTC-")) && timezone_offset_minutes(tz) != 0)
        || tz == "UTC+0"
        || tz == "UTC-0"
}

/// Localized UI strings for the unified Setup / Installer + OOBE flow and compositor sign-in screen.
#[derive(Clone, Copy)]
pub struct L10n {
    pub app_title: &'static str,
    pub welcome_heading: &'static str,
    pub welcome_subtitle: &'static str,
    pub welcome_install_btn: &'static str,
    pub welcome_install_desc: &'static str,
    pub welcome_live_btn: &'static str,
    pub welcome_live_desc: &'static str,
    pub step_install: &'static str,
    pub step_locale: &'static str,
    pub step_timezone: &'static str,
    pub step_network: &'static str,
    pub step_account: &'static str,
    pub step_finish: &'static str,
    pub target_drives: &'static str,
    pub refresh_drives: &'static str,
    pub install_mode: &'static str,
    pub mode_dual: &'static str,
    pub mode_whole: &'static str,
    pub mode_wipe: &'static str,
    pub install_plan: &'static str,
    pub install_now: &'static str,
    pub wipe_and_install: &'static str,
    pub lang_label: &'static str,
    pub kbd_label: &'static str,
    pub kbd_test_label: &'static str,
    pub kbd_test_placeholder: &'static str,
    pub tz_heading: &'static str,
    pub tz_caption: &'static str,
    pub net_heading: &'static str,
    pub net_caption: &'static str,
    pub net_skip: &'static str,
    pub net_dhcp: &'static str,
    pub net_static: &'static str,
    pub acct_heading: &'static str,
    pub acct_caption: &'static str,
    pub acct_optional_hint: &'static str,
    pub acct_username: &'static str,
    pub acct_display: &'static str,
    pub acct_passphrase: &'static str,
    pub acct_operator: &'static str,
    pub finish_heading: &'static str,
    pub finish_unplug: &'static str,
    pub finish_login_note: &'static str,
    pub reboot_now: &'static str,
    pub back: &'static str,
    pub next: &'static str,
    pub skip_for_now: &'static str,
    pub apply_and_finish: &'static str,
    // Lock / Login screen strings (ASCII/Latin-1 safe for compositor TextRender).
    pub lock_boot: &'static str,
    pub lock_manual: &'static str,
    pub lock_idle: &'static str,
    pub lock_sleep: &'static str,
    pub lock_sign_in: &'static str,
    pub lock_unlock: &'static str,
    pub lock_enter_pass: &'static str,
    pub lock_no_pass: &'static str,
    pub lock_invalid_pass: &'static str,
}

impl L10n {
    pub const fn for_lang(lang: Language) -> &'static Self {
        match lang {
            Language::EnUs => &EN_US,
            Language::EnGb => &EN_GB,
            Language::DeDe => &DE_DE,
            Language::FrFr => &FR_FR,
            Language::EsEs => &ES_ES,
        }
    }
}

static EN_US: L10n = L10n {
    app_title: "DiscreteOS Setup",
    welcome_heading: "Welcome to DiscreteOS",
    welcome_subtitle: "Install DiscreteOS and configure your system in one guided flow, or explore the live desktop first.",
    welcome_install_btn: "Install DiscreteOS",
    welcome_install_desc: "Install to an internal drive, then choose language, keyboard, timezone, optional network, and optional account.",
    welcome_live_btn: "Try Live Desktop",
    welcome_live_desc: "Close this window and explore DiscreteOS from live media (read-only).",
    step_install: "Step 1 of 6 — Install DiscreteOS",
    step_locale: "Step 2 of 6 — Language & Keyboard",
    step_timezone: "Step 3 of 6 — Timezone",
    step_network: "Step 4 of 6 — Network (Optional)",
    step_account: "Step 5 of 6 — Local Account (Optional)",
    step_finish: "Step 6 of 6 — Unplug USB & Reboot",
    target_drives: "Target Drives",
    refresh_drives: "Refresh Drives",
    install_mode: "Installation Mode",
    mode_dual: "Dual Boot (Recommended)",
    mode_whole: "Use Entire Disk",
    mode_wipe: "Wipe & Repartition",
    install_plan: "Installation Plan",
    install_now: "Install DiscreteOS",
    wipe_and_install: "Wipe & Install DiscreteOS",
    lang_label: "Language",
    kbd_label: "Keyboard Layout",
    kbd_test_label: "Type here to verify your keyboard layout",
    kbd_test_placeholder: "Test typing symbols and letters...",
    tz_heading: "Select Your Timezone",
    tz_caption: "Hardware clock remains UTC; the desktop clock and apps display local time for this zone.",
    net_heading: "Network Setup (Optional)",
    net_caption: "You can set up internet later in Settings, use automatic DHCP, or enter a static IPv4 address.",
    net_skip: "Set Up Later (Offline)",
    net_dhcp: "Automatic (DHCP)",
    net_static: "Static IPv4",
    acct_heading: "Create a Local Account (Optional)",
    acct_caption: "DiscreteOS has no root user. Each account gets an isolated /home/<user> directory.",
    acct_optional_hint: "Leave username blank to skip account creation and keep the default 'user' identity.",
    acct_username: "Username",
    acct_display: "Display Name",
    acct_passphrase: "Passphrase",
    acct_operator: "Operator role (may manage system settings, apps, and disks)",
    finish_heading: "Installation & Setup Complete",
    finish_unplug: "Please unplug your USB installation drive now, then click Reboot.",
    finish_login_note: "After reboot, you will be welcomed by the DiscreteOS login screen and the installer app will no longer appear.",
    reboot_now: "Reboot Now",
    back: "Back",
    next: "Next",
    skip_for_now: "Skip",
    apply_and_finish: "Save & Complete Setup",
    lock_boot: "Sign in to start your session",
    lock_manual: "Session locked",
    lock_idle: "Locked after inactivity",
    lock_sleep: "Locked before sleep",
    lock_sign_in: "Sign In",
    lock_unlock: "Unlock",
    lock_enter_pass: "Enter passphrase",
    lock_no_pass: "Press Enter to sign in (no passphrase set)",
    lock_invalid_pass: "Invalid passphrase",
};

static EN_GB: L10n = L10n {
    app_title: "DiscreteOS Setup",
    welcome_heading: "Welcome to DiscreteOS",
    welcome_subtitle: "Install DiscreteOS and customise your system in one guided flow, or explore the live desktop first.",
    welcome_install_btn: "Install DiscreteOS",
    welcome_install_desc: "Install to an internal drive, then choose language, keyboard, time zone, optional network, and optional account.",
    welcome_live_btn: "Try Live Desktop",
    welcome_live_desc: "Close this window and explore DiscreteOS from live media (read-only).",
    step_install: "Step 1 of 6 — Install DiscreteOS",
    step_locale: "Step 2 of 6 — Language & Keyboard",
    step_timezone: "Step 3 of 6 — Time Zone",
    step_network: "Step 4 of 6 — Network (Optional)",
    step_account: "Step 5 of 6 — Local Account (Optional)",
    step_finish: "Step 6 of 6 — Unplug USB & Reboot",
    target_drives: "Target Drives",
    refresh_drives: "Refresh Drives",
    install_mode: "Installation Mode",
    mode_dual: "Dual Boot (Recommended)",
    mode_whole: "Use Entire Disk",
    mode_wipe: "Wipe & Repartition",
    install_plan: "Installation Plan",
    install_now: "Install DiscreteOS",
    wipe_and_install: "Wipe & Install DiscreteOS",
    lang_label: "Language",
    kbd_label: "Keyboard Layout",
    kbd_test_label: "Type here to verify your UK keyboard layout (e.g. £, \", @)",
    kbd_test_placeholder: "Test typing symbols and letters...",
    tz_heading: "Select Your Time Zone",
    tz_caption: "Hardware clock remains UTC; the desktop clock and apps display local time for this zone.",
    net_heading: "Network Setup (Optional)",
    net_caption: "You can set up internet later in Settings, use automatic DHCP, or enter a static IPv4 address.",
    net_skip: "Set Up Later (Offline)",
    net_dhcp: "Automatic (DHCP)",
    net_static: "Static IPv4",
    acct_heading: "Create a Local Account (Optional)",
    acct_caption: "DiscreteOS has no root user. Each account gets an isolated /home/<user> directory.",
    acct_optional_hint: "Leave username blank to skip account creation and keep the default 'user' identity.",
    acct_username: "Username",
    acct_display: "Display Name",
    acct_passphrase: "Passphrase",
    acct_operator: "Operator role (may manage system settings, apps, and disks)",
    finish_heading: "Installation & Setup Complete",
    finish_unplug: "Please unplug your USB installation drive now, then click Reboot.",
    finish_login_note: "After reboot, you will be welcomed by the DiscreteOS sign-in screen and the installer app will no longer appear.",
    reboot_now: "Reboot Now",
    back: "Back",
    next: "Next",
    skip_for_now: "Skip",
    apply_and_finish: "Save & Complete Setup",
    lock_boot: "Sign in to start your session",
    lock_manual: "Session locked",
    lock_idle: "Locked after inactivity",
    lock_sleep: "Locked before sleep",
    lock_sign_in: "Sign In",
    lock_unlock: "Unlock",
    lock_enter_pass: "Enter passphrase",
    lock_no_pass: "Press Enter to sign in (no passphrase set)",
    lock_invalid_pass: "Invalid passphrase",
};

static DE_DE: L10n = L10n {
    app_title: "DiscreteOS Einrichtung",
    welcome_heading: "Willkommen bei DiscreteOS",
    welcome_subtitle: "Installieren und konfigurieren Sie DiscreteOS in einem Schritt oder testen Sie zuerst den Live-Desktop.",
    welcome_install_btn: "DiscreteOS installieren",
    welcome_install_desc: "Auf Laufwerk installieren, dann Sprache, Tastatur, Zeitzone, Netzwerk und Konto einrichten.",
    welcome_live_btn: "Live-Desktop testen",
    welcome_live_desc: "Dieses Fenster schliessen und DiscreteOS schreibgeschuetzt testen.",
    step_install: "Schritt 1 von 6 — DiscreteOS installieren",
    step_locale: "Schritt 2 von 6 — Sprache & Tastatur",
    step_timezone: "Schritt 3 von 6 — Zeitzone",
    step_network: "Schritt 4 von 6 — Netzwerk (Optional)",
    step_account: "Schritt 5 von 6 — Lokales Konto (Optional)",
    step_finish: "Schritt 6 von 6 — USB entfernen & Neu starten",
    target_drives: "Ziellaufwerke",
    refresh_drives: "Laufwerke aktualisieren",
    install_mode: "Installationsmodus",
    mode_dual: "Dual-Boot (Empfohlen)",
    mode_whole: "Gesamte Festplatte",
    mode_wipe: "Loeschen & Partitionieren",
    install_plan: "Installationsplan",
    install_now: "DiscreteOS installieren",
    wipe_and_install: "Loeschen & Installieren",
    lang_label: "Sprache",
    kbd_label: "Tastaturlayout",
    kbd_test_label: "Hier tippen, um das Tastaturlayout zu pruefen (z.B. Z/Y, ä ö ü ß)",
    kbd_test_placeholder: "Buchstaben und Zeichen testen...",
    tz_heading: "Zeitzone waehlen",
    tz_caption: "Die Hardwareuhr bleibt auf UTC; die Desktop-Uhr zeigt die Ortszeit dieser Zone.",
    net_heading: "Netzwerk einrichten (Optional)",
    net_caption: "Sie koennen das Internet spaeter in den Einstellungen einrichten, DHCP nutzen oder eine statische IPv4 angeben.",
    net_skip: "Spaeter einrichten (Offline)",
    net_dhcp: "Automatisch (DHCP)",
    net_static: "Statische IPv4",
    acct_heading: "Lokales Konto erstellen (Optional)",
    acct_caption: "DiscreteOS hat keinen Root-Benutzer. Jedes Konto erhaelt ein eigenes /home/<benutzer>.",
    acct_optional_hint: "Benutzernamen leer lassen, um beim Standardkonto 'user' zu bleiben.",
    acct_username: "Benutzername",
    acct_display: "Anzeigename",
    acct_passphrase: "Passphrase",
    acct_operator: "Operator-Rolle (darf Systemeinstellungen, Apps und Laufwerke verwalten)",
    finish_heading: "Installation & Einrichtung abgeschlossen",
    finish_unplug: "Bitte ziehen Sie jetzt den USB-Installationsstick ab und klicken Sie auf Neu starten.",
    finish_login_note: "Nach dem Neustart begruesst Sie der Anmeldebildschirm; die Installer-App erscheint nicht mehr.",
    reboot_now: "Jetzt neu starten",
    back: "Zurueck",
    next: "Weiter",
    skip_for_now: "Ueberspringen",
    apply_and_finish: "Speichern & Abschliessen",
    lock_boot: "Anmelden, um Sitzung zu starten",
    lock_manual: "Sitzung gesperrt",
    lock_idle: "Nach Inaktivitaet gesperrt",
    lock_sleep: "Vor Ruhemodus gesperrt",
    lock_sign_in: "Anmelden",
    lock_unlock: "Entsperren",
    lock_enter_pass: "Passphrase eingeben",
    lock_no_pass: "Enter druecken zum Anmelden (kein Passwort)",
    lock_invalid_pass: "Ungueltige Passphrase",
};

static FR_FR: L10n = L10n {
    app_title: "Installation de DiscreteOS",
    welcome_heading: "Bienvenue dans DiscreteOS",
    welcome_subtitle: "Installez et configurez DiscreteOS en une seule fenetre, ou essayez d'abord le bureau live.",
    welcome_install_btn: "Installer DiscreteOS",
    welcome_install_desc: "Installer sur un disque, puis choisir langue, clavier, fuseau horaire, reseau et compte.",
    welcome_live_btn: "Essayer le bureau Live",
    welcome_live_desc: "Fermer cette fenetre et decouvrir DiscreteOS en lecture seule.",
    step_install: "Etape 1 sur 6 — Installer DiscreteOS",
    step_locale: "Etape 2 sur 6 — Langue et Clavier",
    step_timezone: "Etape 3 sur 6 — Fuseau horaire",
    step_network: "Etape 4 sur 6 — Reseau (Facultatif)",
    step_account: "Etape 5 sur 6 — Compte local (Facultatif)",
    step_finish: "Etape 6 sur 6 — Retirer la cle USB et Redemarrer",
    target_drives: "Disques cibles",
    refresh_drives: "Actualiser les disques",
    install_mode: "Mode d'installation",
    mode_dual: "Dual Boot (Recommande)",
    mode_whole: "Disque entier",
    mode_wipe: "Effacer et Partitionner",
    install_plan: "Plan d'installation",
    install_now: "Installer DiscreteOS",
    wipe_and_install: "Effacer et Installer",
    lang_label: "Langue",
    kbd_label: "Disposition du clavier",
    kbd_test_label: "Tapez ici pour verifier le clavier (ex. AZERTY, é è ç à)",
    kbd_test_placeholder: "Tester les lettres et symboles...",
    tz_heading: "Choisir votre fuseau horaire",
    tz_caption: "L'horloge materielle reste en UTC ; le bureau affiche l'heure locale de cette zone.",
    net_heading: "Configuration reseau (Facultatif)",
    net_caption: "Vous pourrez configurer internet plus tard, utiliser DHCP automatique ou une IPv4 statique.",
    net_skip: "Configurer plus tard (Hors ligne)",
    net_dhcp: "Automatique (DHCP)",
    net_static: "IPv4 statique",
    acct_heading: "Creer un compte local (Facultatif)",
    acct_caption: "DiscreteOS n'a pas de compte root. Chaque compte dispose de son dossier /home/<utilisateur>.",
    acct_optional_hint: "Laissez le nom d'utilisateur vide pour conserver le compte par defaut 'user'.",
    acct_username: "Identifiant",
    acct_display: "Nom complet",
    acct_passphrase: "Phrase de passe",
    acct_operator: "Role Operateur (gestion des parametres, applications et disques)",
    finish_heading: "Installation et configuration terminees",
    finish_unplug: "Debranchez maintenant votre cle USB d'installation, puis cliquez sur Redemarrer.",
    finish_login_note: "Au redemarrage, l'ecran de connexion s'affichera et l'installateur ne sera plus present.",
    reboot_now: "Redemarrer maintenant",
    back: "Retour",
    next: "Suivant",
    skip_for_now: "Ignorer",
    apply_and_finish: "Enregistrer et Terminer",
    lock_boot: "Connectez-vous pour demarrer",
    lock_manual: "Session verrouillee",
    lock_idle: "Verrouillee apres inactivite",
    lock_sleep: "Verrouillee avant mise en veille",
    lock_sign_in: "Se connecter",
    lock_unlock: "Deverrouiller",
    lock_enter_pass: "Entrer la phrase de passe",
    lock_no_pass: "Appuyez sur Entree (aucun mot de passe)",
    lock_invalid_pass: "Phrase de passe invalide",
};

static ES_ES: L10n = L10n {
    app_title: "Instalacion de DiscreteOS",
    welcome_heading: "Bienvenido a DiscreteOS",
    welcome_subtitle: "Instala y configura DiscreteOS en una sola ventana, o prueba primero el escritorio en vivo.",
    welcome_install_btn: "Instalar DiscreteOS",
    welcome_install_desc: "Instala en un disco y elige idioma, teclado, zona horaria, red opcional y cuenta opcional.",
    welcome_live_btn: "Probar escritorio Live",
    welcome_live_desc: "Cierra esta ventana para explorar DiscreteOS en modo solo lectura.",
    step_install: "Paso 1 de 6 — Instalar DiscreteOS",
    step_locale: "Paso 2 de 6 — Idioma y Teclado",
    step_timezone: "Paso 3 de 6 — Zona horaria",
    step_network: "Paso 4 de 6 — Red (Opcional)",
    step_account: "Paso 5 de 6 — Cuenta local (Opcional)",
    step_finish: "Paso 6 de 6 — Desconectar USB y Reiniciar",
    target_drives: "Discos de destino",
    refresh_drives: "Actualizar discos",
    install_mode: "Modo de instalacion",
    mode_dual: "Arranque dual (Recomendado)",
    mode_whole: "Usar todo el disco",
    mode_wipe: "Borrar y Reparticionar",
    install_plan: "Plan de instalacion",
    install_now: "Instalar DiscreteOS",
    wipe_and_install: "Borrar e Instalar",
    lang_label: "Idioma",
    kbd_label: "Distribucion de teclado",
    kbd_test_label: "Escribe aqui para verificar tu teclado (ej. ñ, ¡, ¿, @)",
    kbd_test_placeholder: "Prueba escribiendo letras y simbolos...",
    tz_heading: "Selecciona tu zona horaria",
    tz_caption: "El reloj de hardware sigue en UTC; el escritorio muestra la hora local de esta zona.",
    net_heading: "Configuracion de red (Opcional)",
    net_caption: "Puedes configurar internet mas tarde en Ajustes, usar DHCP automatico o IPv4 estatica.",
    net_skip: "Configurar mas tarde (Sin red)",
    net_dhcp: "Automatico (DHCP)",
    net_static: "IPv4 estatica",
    acct_heading: "Crear cuenta local (Opcional)",
    acct_caption: "DiscreteOS no tiene usuario root. Cada cuenta recibe su propio /home/<usuario>.",
    acct_optional_hint: "Deja el usuario en blanco para mantener la cuenta predeterminada 'user'.",
    acct_username: "Usuario",
    acct_display: "Nombre visible",
    acct_passphrase: "Contrasena",
    acct_operator: "Rol Operador (puede administrar ajustes, aplicaciones y discos)",
    finish_heading: "Instalacion y configuracion completas",
    finish_unplug: "Desconecta ahora tu memoria USB de instalacion y haz clic en Reiniciar.",
    finish_login_note: "Al reiniciar veras la pantalla de inicio de sesion y la app instaladora ya no aparecera.",
    reboot_now: "Reiniciar ahora",
    back: "Atras",
    next: "Siguiente",
    skip_for_now: "Omitir",
    apply_and_finish: "Guardar y Finalizar",
    lock_boot: "Inicia sesion para comenzar",
    lock_manual: "Sesion bloqueada",
    lock_idle: "Bloqueada por inactividad",
    lock_sleep: "Bloqueada antes de suspender",
    lock_sign_in: "Iniciar sesion",
    lock_unlock: "Desbloquear",
    lock_enter_pass: "Introduce la contrasena",
    lock_no_pass: "Pulsa Enter para entrar (sin contrasena)",
    lock_invalid_pass: "Contrasena incorrecta",
};

/// Map a PC scancode Set 1 / Linux keycode (`1..=57`, plus ISO 102nd key `86`) through any of the
/// 5 supported keyboard layouts (`us`, `uk`, `de`, `fr`, `es`) with `shift`, `altgr`, and `caps`.
/// Returns a Unicode Latin-1 codepoint (`0x01..=0xFF`, e.g. `£`=0xA3, `ä`=0xE4, `é`=0xE9, `ñ`=0xF1).
pub fn map_layout_codepoint(layout: KeyboardLayout, code: u16, shift: bool, altgr: bool, caps: bool) -> Option<u32> {
    // Base US QWERTY tables (indices 0..58).
    const US_PLAIN: [u8; 58] = *b"\0\x1b1234567890-=\x08\tqwertyuiop[]\n\0asdfghjkl;'`\0\\zxcvbnm,./\0*\0 ";
    const US_SHIFT: [u8; 58] = *b"\0\x1b!@#$%^&*()_+\x08\tQWERTYUIOP{}\n\0ASDFGHJKL:\"~\0|ZXCVBNM<>?\0*\0 ";

    // ISO 102nd key (between Left Shift and Z/Y, Linux keycode 86 / PS2 0x56 / HID 0x64).
    if code == 86 {
        let ch: u32 = match layout {
            KeyboardLayout::Us | KeyboardLayout::Uk => if shift { b'|' as u32 } else { b'\\' as u32 },
            KeyboardLayout::De => if altgr { b'|' as u32 } else if shift { b'>' as u32 } else { b'<' as u32 },
            KeyboardLayout::Fr | KeyboardLayout::Es => if shift { b'>' as u32 } else { b'<' as u32 },
        };
        return Some(ch);
    }

    let idx = usize::from(code);
    if idx >= 58 {
        return None;
    }

    // AltGr (Right Alt) overrides for European layouts.
    if altgr {
        let ag: Option<u32> = match layout {
            KeyboardLayout::De => match code {
                8 => Some(b'{' as u32),  // 7
                9 => Some(b'[' as u32),  // 8
                10 => Some(b']' as u32), // 9
                11 => Some(b'}' as u32), // 0
                12 => Some(b'\\' as u32),// ß
                16 => Some(b'@' as u32), // Q
                27 => Some(b'~' as u32), // +
                50 => Some(0xB5),        // M -> µ
                _ => None,
            },
            KeyboardLayout::Fr => match code {
                3 => Some(b'~' as u32),  // 2
                4 => Some(b'#' as u32),  // 3
                5 => Some(b'{' as u32),  // 4
                6 => Some(b'[' as u32),  // 5
                7 => Some(b'|' as u32),  // 6
                8 => Some(b'`' as u32),  // 7
                9 => Some(b'\\' as u32), // 8
                10 => Some(b'^' as u32), // 9
                11 => Some(b'@' as u32), // 0
                12 => Some(b']' as u32), // )
                13 => Some(b'}' as u32), // =
                _ => None,
            },
            KeyboardLayout::Es => match code {
                2 => Some(b'|' as u32),  // 1
                3 => Some(b'@' as u32),  // 2
                4 => Some(b'#' as u32),  // 3
                5 => Some(b'~' as u32),  // 4
                26 => Some(b'[' as u32), // `
                27 => Some(b']' as u32), // +
                40 => Some(b'{' as u32), // ´
                43 => Some(b'}' as u32), // ç
                41 => Some(b'\\' as u32),// º
                _ => None,
            },
            KeyboardLayout::Uk => match code {
                41 => Some(b'|' as u32),
                _ => None,
            },
            KeyboardLayout::Us => None,
        };
        if ag.is_some() {
            return ag;
        }
    }

    // Per-layout plain & shifted character override (codepoints in 0x01..=0xFF).
    let raw: u32 = match layout {
        KeyboardLayout::Us => u32::from(if shift { US_SHIFT[idx] } else { US_PLAIN[idx] }),
        KeyboardLayout::Uk => match (code, shift) {
            (3, true) => b'"' as u32,
            (4, true) => 0xA3, // £
            (40, true) => b'@' as u32,
            (41, false) => b'`' as u32,
            (41, true) => 0xAC, // ¬
            (43, false) => b'#' as u32,
            (43, true) => b'~' as u32,
            _ => u32::from(if shift { US_SHIFT[idx] } else { US_PLAIN[idx] }),
        },
        KeyboardLayout::De => match (code, shift) {
            (3, true) => b'"' as u32,
            (4, true) => 0xA7, // §
            (7, true) => b'&' as u32,
            (8, true) => b'/' as u32,
            (9, true) => b'(' as u32,
            (10, true) => b')' as u32,
            (11, true) => b'=' as u32,
            (12, false) => 0xDF, // ß
            (12, true) => b'?' as u32,
            (13, false) => 0xB4, // ´
            (13, true) => b'`' as u32,
            (21, false) => b'z' as u32, // Y -> Z
            (21, true) => b'Z' as u32,
            (26, false) => 0xFC, // ü
            (26, true) => 0xDC,  // Ü
            (27, false) => b'+' as u32,
            (27, true) => b'*' as u32,
            (39, false) => 0xF6, // ö
            (39, true) => 0xD6,  // Ö
            (40, false) => 0xE4, // ä
            (40, true) => 0xC4,  // Ä
            (41, false) => b'^' as u32,
            (41, true) => 0xB0, // °
            (43, false) => b'#' as u32,
            (43, true) => b'\'' as u32,
            (44, false) => b'y' as u32, // Z -> Y
            (44, true) => b'Y' as u32,
            (51, true) => b';' as u32,
            (52, true) => b':' as u32,
            (53, false) => b'-' as u32,
            (53, true) => b'_' as u32,
            _ => u32::from(if shift { US_SHIFT[idx] } else { US_PLAIN[idx] }),
        },
        KeyboardLayout::Fr => match (code, shift) {
            (2, false) => b'&' as u32,
            (2, true) => b'1' as u32,
            (3, false) => 0xE9, // é
            (3, true) => b'2' as u32,
            (4, false) => b'"' as u32,
            (4, true) => b'3' as u32,
            (5, false) => b'\'' as u32,
            (5, true) => b'4' as u32,
            (6, false) => b'(' as u32,
            (6, true) => b'5' as u32,
            (7, false) => b'-' as u32,
            (7, true) => b'6' as u32,
            (8, false) => 0xE8, // è
            (8, true) => b'7' as u32,
            (9, false) => b'_' as u32,
            (9, true) => b'8' as u32,
            (10, false) => 0xE7, // ç
            (10, true) => b'9' as u32,
            (11, false) => 0xE0, // à
            (11, true) => b'0' as u32,
            (12, false) => b')' as u32,
            (12, true) => 0xB0, // °
            (13, false) => b'=' as u32,
            (13, true) => b'+' as u32,
            (16, false) => b'a' as u32, // Q -> A
            (16, true) => b'A' as u32,
            (17, false) => b'z' as u32, // W -> Z
            (17, true) => b'Z' as u32,
            (26, false) => b'^' as u32,
            (26, true) => 0xA8, // ¨
            (27, false) => b'$' as u32,
            (27, true) => 0xA3, // £
            (30, false) => b'q' as u32, // A -> Q
            (30, true) => b'Q' as u32,
            (39, false) => b'm' as u32, // ; -> M
            (39, true) => b'M' as u32,
            (40, false) => 0xF9, // ù
            (40, true) => b'%' as u32,
            (41, false) => 0xB2, // ²
            (41, true) => 0xB2,
            (43, false) => b'*' as u32,
            (43, true) => 0xB5, // µ
            (44, false) => b'w' as u32, // Z -> W
            (44, true) => b'W' as u32,
            (50, false) => b',' as u32, // M -> ,
            (50, true) => b'?' as u32,
            (51, false) => b';' as u32,
            (51, true) => b'.' as u32,
            (52, false) => b':' as u32,
            (52, true) => b'/' as u32,
            (53, false) => b'!' as u32,
            (53, true) => 0xA7, // §
            _ => u32::from(if shift { US_SHIFT[idx] } else { US_PLAIN[idx] }),
        },
        KeyboardLayout::Es => match (code, shift) {
            (3, true) => b'"' as u32,
            (4, true) => 0xB7, // ·
            (7, true) => b'&' as u32,
            (8, true) => b'/' as u32,
            (9, true) => b'(' as u32,
            (10, true) => b')' as u32,
            (11, true) => b'=' as u32,
            (12, false) => b'\'' as u32,
            (12, true) => b'?' as u32,
            (13, false) => 0xA1, // ¡
            (13, true) => 0xBF,  // ¿
            (26, false) => b'`' as u32,
            (26, true) => b'^' as u32,
            (27, false) => b'+' as u32,
            (27, true) => b'*' as u32,
            (39, false) => 0xF1, // ñ
            (39, true) => 0xD1,  // Ñ
            (40, false) => 0xB4, // ´
            (40, true) => 0xA8,  // ¨
            (41, false) => 0xBA, // º
            (41, true) => 0xAA,  // ª
            (43, false) => 0xE7, // ç
            (43, true) => 0xC7,  // Ç
            (51, true) => b';' as u32,
            (52, true) => b':' as u32,
            (53, false) => b'-' as u32,
            (53, true) => b'_' as u32,
            _ => u32::from(if shift { US_SHIFT[idx] } else { US_PLAIN[idx] }),
        },
    };

    if raw == 0 {
        return None;
    }

    let mut out = raw;
    if caps {
        if (b'a' as u32..=b'z' as u32).contains(&out) {
            out -= 32;
        } else if (b'A' as u32..=b'Z' as u32).contains(&out) {
            out += 32;
        } else if matches!(out, 0xE4 | 0xF6 | 0xFC | 0xF1 | 0xE7) {
            // ä ö ü ñ ç -> Ä Ö Ü Ñ Ç
            out -= 32;
        } else if matches!(out, 0xC4 | 0xD6 | 0xDC | 0xD1 | 0xC7) {
            out += 32;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_five_languages_have_distinct_translations() {
        for lang in Language::ALL {
            let l = L10n::for_lang(lang);
            assert!(!l.welcome_heading.is_empty());
            assert!(!l.reboot_now.is_empty());
            assert!(!l.lock_sign_in.is_empty());
            assert_eq!(Language::from_code(lang.code()), lang);
            assert_eq!(Language::from_id(lang.id()), lang);
        }
        assert_ne!(L10n::for_lang(Language::EnUs).welcome_heading, L10n::for_lang(Language::DeDe).welcome_heading);
        assert_ne!(L10n::for_lang(Language::DeDe).welcome_heading, L10n::for_lang(Language::FrFr).welcome_heading);
        assert_ne!(L10n::for_lang(Language::FrFr).welcome_heading, L10n::for_lang(Language::EsEs).welcome_heading);
        assert_ne!(L10n::for_lang(Language::EnUs).step_timezone, L10n::for_lang(Language::EnGb).step_timezone);
    }

    #[test]
    fn all_five_keyboard_layouts_verified() {
        // US QWERTY
        assert_eq!(map_layout_codepoint(KeyboardLayout::Us, 21, false, false, false), Some(b'y' as u32));
        assert_eq!(map_layout_codepoint(KeyboardLayout::Us, 44, false, false, false), Some(b'z' as u32));
        assert_eq!(map_layout_codepoint(KeyboardLayout::Us, 3, true, false, false), Some(b'@' as u32));
        assert_eq!(map_layout_codepoint(KeyboardLayout::Us, 4, true, false, false), Some(b'#' as u32));

        // UK QWERTY
        assert_eq!(map_layout_codepoint(KeyboardLayout::Uk, 3, true, false, false), Some(b'"' as u32));
        assert_eq!(map_layout_codepoint(KeyboardLayout::Uk, 4, true, false, false), Some(0xA3)); // £
        assert_eq!(map_layout_codepoint(KeyboardLayout::Uk, 40, true, false, false), Some(b'@' as u32));
        assert_eq!(map_layout_codepoint(KeyboardLayout::Uk, 43, false, false, false), Some(b'#' as u32));
        assert_eq!(map_layout_codepoint(KeyboardLayout::Uk, 43, true, false, false), Some(b'~' as u32));

        // German QWERTZ
        assert_eq!(map_layout_codepoint(KeyboardLayout::De, 21, false, false, false), Some(b'z' as u32));
        assert_eq!(map_layout_codepoint(KeyboardLayout::De, 44, false, false, false), Some(b'y' as u32));
        assert_eq!(map_layout_codepoint(KeyboardLayout::De, 12, false, false, false), Some(0xDF)); // ß
        assert_eq!(map_layout_codepoint(KeyboardLayout::De, 26, false, false, false), Some(0xFC)); // ü
        assert_eq!(map_layout_codepoint(KeyboardLayout::De, 39, false, false, false), Some(0xF6)); // ö
        assert_eq!(map_layout_codepoint(KeyboardLayout::De, 40, false, false, false), Some(0xE4)); // ä
        assert_eq!(map_layout_codepoint(KeyboardLayout::De, 40, false, false, true), Some(0xC4));  // Ä (Caps)
        assert_eq!(map_layout_codepoint(KeyboardLayout::De, 16, false, true, false), Some(b'@' as u32)); // AltGr+Q
        assert_eq!(map_layout_codepoint(KeyboardLayout::De, 86, false, true, false), Some(b'|' as u32)); // AltGr+<

        // French AZERTY
        assert_eq!(map_layout_codepoint(KeyboardLayout::Fr, 16, false, false, false), Some(b'a' as u32));
        assert_eq!(map_layout_codepoint(KeyboardLayout::Fr, 17, false, false, false), Some(b'z' as u32));
        assert_eq!(map_layout_codepoint(KeyboardLayout::Fr, 30, false, false, false), Some(b'q' as u32));
        assert_eq!(map_layout_codepoint(KeyboardLayout::Fr, 44, false, false, false), Some(b'w' as u32));
        assert_eq!(map_layout_codepoint(KeyboardLayout::Fr, 39, false, false, false), Some(b'm' as u32));
        assert_eq!(map_layout_codepoint(KeyboardLayout::Fr, 50, false, false, false), Some(b',' as u32));
        assert_eq!(map_layout_codepoint(KeyboardLayout::Fr, 3, false, false, false), Some(0xE9)); // é
        assert_eq!(map_layout_codepoint(KeyboardLayout::Fr, 3, true, false, false), Some(b'2' as u32));
        assert_eq!(map_layout_codepoint(KeyboardLayout::Fr, 11, false, true, false), Some(b'@' as u32)); // AltGr+à

        // Spanish QWERTY
        assert_eq!(map_layout_codepoint(KeyboardLayout::Es, 39, false, false, false), Some(0xF1)); // ñ
        assert_eq!(map_layout_codepoint(KeyboardLayout::Es, 39, true, false, false), Some(0xD1));  // Ñ
        assert_eq!(map_layout_codepoint(KeyboardLayout::Es, 13, false, false, false), Some(0xA1)); // ¡
        assert_eq!(map_layout_codepoint(KeyboardLayout::Es, 13, true, false, false), Some(0xBF));  // ¿
        assert_eq!(map_layout_codepoint(KeyboardLayout::Es, 3, false, true, false), Some(b'@' as u32)); // AltGr+2
    }

    #[test]
    fn timezone_offsets_parse_accurately() {
        assert_eq!(timezone_offset_minutes("UTC"), 0);
        assert_eq!(timezone_offset_minutes("UTC-8"), -480);
        assert_eq!(timezone_offset_minutes("UTC-7"), -420);
        assert_eq!(timezone_offset_minutes("UTC-6"), -360);
        assert_eq!(timezone_offset_minutes("UTC-5"), -300);
        assert_eq!(timezone_offset_minutes("UTC+0"), 0);
        assert_eq!(timezone_offset_minutes("UTC+1"), 60);
        assert_eq!(timezone_offset_minutes("UTC+9"), 540);
        assert_eq!(timezone_offset_minutes("bogus"), 0);
        for (tz, _) in TIMEZONES {
            assert!(is_valid_timezone(tz));
        }
    }
}
