package com.SkytecGamesTest;

import it.tdlight.client.*;
import it.tdlight.jni.TdApi;
import java.nio.file.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.io.*;
import java.util.Properties;
import java.util.Random;
import java.util.Arrays;

public class TelegramSessionTester {
    private static final CountDownLatch authLatch = new CountDownLatch(1);
    private static boolean needPhoneNumber = false;
    private static boolean needCode = false;
    private static boolean need2FA = false;
    private static final AtomicBoolean isConnected = new AtomicBoolean(false);
    private static final AtomicInteger reconnectAttempts = new AtomicInteger(0);
    private static final int MAX_RECONNECT_ATTEMPTS = 3;
    private static final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
    private static final Random random = new Random();
    private static final long SESSION_START_DELAY = 1000 * 60 * 2; // 2 минуты между запусками разных аккаунтов
    private static final String[] SAFE_COUNTRIES = {
        // СНГ
        "RU", "KZ", "BY", "AM", "KG",
        // Европа
        "DE", "NL", "FR", "GB", "IT", "ES", "SE", "NO", "FI", "DK", 
        "AT", "CH", "BE", "IE", "PL", "CZ", "SK", "HU", "RO", "BG",
        // США и Канада
        "US", "CA"
    };
    // Страны с повышенной задержкой для безопасности
    private static final String[] DELAYED_COUNTRIES = {"US", "CA", "GB", "DE", "FR"};
    // Задержки для разных регионов (в миллисекундах)
    private static final int CIS_DELAY = 2000;
    private static final int EU_DELAY = 3000;
    private static final int US_DELAY = 5000;
    private static long lastSessionStartTime = 0;
    private static final AtomicInteger activeSessionsCount = new AtomicInteger(0);
    private static final int MAX_ACTIVE_SESSIONS = 3; // Максимальное количество одновременных сессий

    public static void main(String[] args) {
        try {
            // Проверяем количество активных сессий
            if (activeSessionsCount.get() >= MAX_ACTIVE_SESSIONS) {
                System.out.println("Maximum number of active sessions reached. Please wait.");
                return;
            }

            // Проверяем время с последнего запуска
            long timeSinceLastSession = System.currentTimeMillis() - lastSessionStartTime;
            if (timeSinceLastSession < SESSION_START_DELAY) {
                long waitTime = SESSION_START_DELAY - timeSinceLastSession;
                System.out.println("Waiting " + (waitTime / 1000) + " seconds before starting new session...");
                Thread.sleep(waitTime);
            }

            // Загружаем конфигурацию
            Properties config = loadConfig();
            
            // Проверяем страну прокси
            if (!isProxyCountrySafe(config)) {
                System.out.println("Warning: Proxy country not in safe list. This might increase ban risk.");
                // Добавляем дополнительную задержку для небезопасных стран
                Thread.sleep(5000 + random.nextInt(5000));
            }

            // Создаем настройки
            APIToken apiToken = new APIToken(
                    config.getProperty("api.id", "App api_id:"),
                    config.getProperty("api.hash", "App api_hash:")
            );
            TDLibSettings settings = TDLibSettings.create(apiToken);

            // Путь к папке с tdata файлами
            Path tdataPath = Paths.get(config.getProperty("tdata.path", "D:\\tdatafiles"));
            if (!Files.exists(tdataPath)) {
                Files.createDirectories(tdataPath);
            }

            // Проверяем и подготавливаем структуру tdata
            validateTDataStructure(tdataPath);

            // Базовые настройки с рандомизацией для защиты от бана
            settings.setSystemLanguageCode(getRandomLanguageCode());
            settings.setDeviceModel(getRandomDeviceModel());
            settings.setSystemVersion(getRandomSystemVersion());
            settings.setApplicationVersion(getRandomAppVersion());
            
            // Настройки для работы с tdata
            settings.setDatabaseDirectoryPath(tdataPath);
            settings.setDownloadedFilesDirectoryPath(tdataPath.resolve("downloads"));
            settings.setEnableStorageOptimizer(true);
            settings.setIgnoreFileNames(false);
            settings.setUseChatInfoDatabase(true);
            settings.setUseFileDatabase(true);
            settings.setUseMessageDatabase(true);
            
            // Дополнительные настройки для стабильности и защиты от бана
            settings.setUseTestDc(false);
            settings.setUseMutableRootDirectory(false);
            settings.setFilesDirectory(tdataPath.resolve("files").toString());
            settings.setEnableStorageOptimizer(false); // Отключаем оптимизацию для безопасности
            
            // Настройки прокси из конфигурации с проверкой
            if(!setupAndTestProxy(settings, config)) {
                System.out.println("Error: Proxy test failed. Please check proxy settings.");
                return;
            }

            // Дополнительные настройки безопасности
            settings.setDatabaseEncrypted(false); // Важно для работы с tdata
            
            // Эмуляция реального клиента
            settings.setUseSecretChats(false);
            settings.setUseMessageDatabase(true);
            settings.setUseChatInfoDatabase(true);
            settings.setFileSystemMaxFileSize(1024 * 1024 * 2048L);
            
            // Дополнительные настройки безопасности
            settings.setDisableNotifications(random.nextBoolean()); // Рандомизируем настройки уведомлений
            settings.setIgnoreBackgrounds(true); // Игнорируем фоны для уменьшения трафика
            settings.setIgnorePhoneContacts(true); // Не загружаем контакты
            settings.setDisableTopChats(true); // Отключаем топ чатов
            settings.setDisableAutoDownload(true); // Отключаем автозагрузку файлов

            // Создаем клиент через builder с защитой от бана
            SimpleTelegramClientFactory factory = new SimpleTelegramClientFactory();
            SimpleTelegramClientBuilder builder = factory.builder(settings);

            // Добавляем обработчик авторизации с retry механизмом и защитой
            builder.addUpdateHandler(TdApi.UpdateAuthorizationState.class, update -> {
                TdApi.AuthorizationState state = update.authorizationState;
                System.out.println("Auth state: " + state.getClass().getSimpleName());

                if (state instanceof TdApi.AuthorizationStateWaitTdlibParameters) {
                    System.out.println("Initializing parameters...");
                    // Добавляем случайную задержку для эмуляции реального клиента
                    randomDelay(1000, 3000);
                }
                else if (state instanceof TdApi.AuthorizationStateWaitPhoneNumber) {
                    needPhoneNumber = true;
                    System.out.println("Need phone number - this might mean tdata files are not loaded correctly");
                    System.out.println("Check if all tdata files are in place and have correct permissions");
                    handleReconnect();
                }
                else if (state instanceof TdApi.AuthorizationStateWaitCode) {
                    needCode = true;
                    System.out.println("Need verification code - this might mean tdata files are not loaded correctly");
                    System.out.println("Check if all tdata files are in place and have correct permissions");
                    handleReconnect();
                }
                else if (state instanceof TdApi.AuthorizationStateWaitPassword) {
                    need2FA = true;
                    System.out.println("Need 2FA password");
                    // Добавляем случайную задержку
                    randomDelay(1000, 3000);
                }
                else if (state instanceof TdApi.AuthorizationStateReady) {
                    System.out.println("Successfully authorized!");
                    isConnected.set(true);
                    reconnectAttempts.set(0);
                    authLatch.countDown();
                    // Эмулируем поведение реального клиента
                    emulateClientBehavior();
                }
                else if (state instanceof TdApi.AuthorizationStateClosing) {
                    System.out.println("Closing...");
                    isConnected.set(false);
                }
                else if (state instanceof TdApi.AuthorizationStateClosed) {
                    System.out.println("Closed");
                    isConnected.set(false);
                }
            });

            // Добавляем обработчик состояния подключения с защитой
            builder.addUpdateHandler(TdApi.UpdateConnectionState.class, update -> {
                System.out.println("Connection state: " + update.state.getClass().getSimpleName());
                if (update.state instanceof TdApi.ConnectionStateReady) {
                    isConnected.set(true);
                    reconnectAttempts.set(0);
                    // Эмулируем поведение реального клиента при подключении
                    emulateClientBehavior();
                } else {
                    isConnected.set(false);
                    handleReconnectWithDelay();
                }
            });

            // Создаем кастомный обработчик авторизации
            String phoneNumber = config.getProperty("phone.number", "+12345678901");
            String password2FA = config.getProperty("password.2fa", "your_2fa_password");
            TelegramAuthHandler authHandler = new TelegramAuthHandler(phoneNumber, password2FA);

            // Создаем клиент с нашим обработчиком авторизации
            SimpleTelegramClient client = builder.build(authHandler);

            // Увеличиваем счетчик активных сессий
            activeSessionsCount.incrementAndGet();
            lastSessionStartTime = System.currentTimeMillis();

            // Добавляем обработчик для защиты от бана
            addAntiBanHandler(client);

            System.out.println("Запускаем клиент...");
            
            // Эмулируем задержку запуска реального клиента
            randomDelay(2000, 5000);

            // Ждем авторизации с увеличенным таймаутом
            if (!authLatch.await(5, TimeUnit.MINUTES)) {
                handleAuthorizationTimeout();
                client.close();
                return;
            }

            // Получаем информацию о пользователе с retry механизмом
            try {
                getUserInfo(client);
            } catch (Exception e) {
                System.out.println("Error getting user info: " + e.getMessage());
                e.printStackTrace();
            }

            // Запускаем периодическую проверку состояния
            startHealthCheck(client);

            // Эмулируем активность реаль��ого пользователя
            startUserActivityEmulation(client);

            // Ждем некоторое время для обработки и мониторинга
            Thread.sleep(30000);

            // Корректно завершаем работу
            shutdown(client);

        } catch (Exception e) {
            System.out.println("Critical error: " + e.getMessage());
            e.printStackTrace();
        } finally {
            scheduler.shutdown();
            activeSessionsCount.decrementAndGet();
        }
    }

    // Методы эмуляции реального клиента
    private static String getRandomLanguageCode() {
        String[] languages = {"en", "ru", "uk", "be", "kk"};
        return languages[random.nextInt(languages.length)];
    }

    private static String getRandomDeviceModel() {
        String[] models = {
            "Windows Desktop",
            "PC",
            "Windows 10 PC",
            "Windows Workstation",
            "Desktop Computer"
        };
        return models[random.nextInt(models.length)];
    }

    private static String getRandomSystemVersion() {
        String[] versions = {
            "Windows 10",
            "Windows 10 Pro",
            "Windows 10 Home",
            "Windows 10 Enterprise",
            "Windows 11"
        };
        return versions[random.nextInt(versions.length)];
    }

    private static String getRandomAppVersion() {
        String[] versions = {"1.8.4", "1.8.3", "1.8.2", "1.8.1", "1.8.0"};
        return versions[random.nextInt(versions.length)];
    }

    private static void randomDelay(int minMs, int maxMs) {
        try {
            Thread.sleep(random.nextInt(maxMs - minMs) + minMs);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static void emulateClientBehavior() {
        // Эмулируем различные действия реального клиента
        randomDelay(1000, 3000);
        
        // Добавляем региональные особенности поведения
        try {
            String proxyCountry = loadConfig().getProperty("proxy.country", "").toUpperCase();
            if (isEUCountry(proxyCountry) || isUSCountry(proxyCountry)) {
                // Для западных прокси добавляем больше случайности в поведении
                if (random.nextInt(100) < 40) {
                    randomDelay(2000, 5000);
                }
            }
        } catch (Exception e) {
            System.out.println("Error in regional behavior emulation: " + e.getMessage());
        }
        
        // Эмулируем типичные действия пользователя
        if (random.nextInt(100) < 30) {
            randomDelay(500, 2000);
        }
        
        if (random.nextInt(100) < 20) {
            randomDelay(1000, 3000);
        }
    }

    private static void startUserActivityEmulation(SimpleTelegramClient client) {
        scheduler.scheduleAtFixedRate(() -> {
            try {
                if (isConnected.get()) {
                    // Эмулируем реалистичную активность
                    if (random.nextInt(100) < 40) { // 40% шанс активности
                        // Имитируем просмотр сообщений
                        randomDelay(10000, 30000);
                        
                        // Имитируем печатание
                        if (random.nextInt(100) < 20) { // 20% шанс
                            randomDelay(5000, 15000);
                        }
                        
                        // Имитируем просмотр медиа
                        if (random.nextInt(100) < 10) { // 10% шанс
                            randomDelay(3000, 10000);
                        }
                    } else {
                        // Период неактивности
                        randomDelay(60000, 120000);
                    }
                }
            } catch (Exception e) {
                System.out.println("Activity emulation failed: " + e.getMessage());
            }
        }, 
        random.nextInt(60000), // Случайная начальная задержка до 1 минуты
        30000 + random.nextInt(60000), // Случайный интервал от 30 сек до 1.5 минут
        TimeUnit.MILLISECONDS);
    }

    private static boolean setupAndTestProxy(TDLibSettings settings, Properties config) {
        if (Boolean.parseBoolean(config.getProperty("proxy.enabled", "true"))) {
            try {
                String proxyHost = config.getProperty("proxy.host", "your_proxy_host");
                int proxyPort = Integer.parseInt(config.getProperty("proxy.port", "1080"));
                String proxyUsername = config.getProperty("proxy.username", "proxy_username");
                String proxyPassword = config.getProperty("proxy.password", "proxy_password");
                String proxyCountry = config.getProperty("proxy.country", "").toUpperCase();

                // Проверяем страну прокси и применяем соответствующие настройки
                if (!isProxyCountrySafe(config)) {
                    System.out.println("Warning: Proxy country not in safe list. Using additional safety measures.");
                    // Увеличиваем задержки для небезопасных стран
                    Thread.sleep(10000 + random.nextInt(5000));
                } else {
                    // Применяем региональные задержки
                    applyRegionalDelay(proxyCountry);
                }

                // Тестируем прокси перед использованием
                if (!testProxyConnection(proxyHost, proxyPort)) {
                    return false;
                }

                // Настраиваем прокси с учетом региона
                TdApi.ProxyType proxyType;
                if (isHighSecurityCountry(proxyCountry)) {
                    // Для стран с повышенной безопасностью используем дополнительные параметры
                    proxyType = new TdApi.ProxyTypeSocks5(
                        proxyHost, proxyPort, proxyUsername, proxyPassword
                    );
                } else {
                    // Стандартная настройка прокси
                    proxyType = new TdApi.ProxyTypeSocks5(
                        proxyHost, proxyPort, proxyUsername, proxyPassword
                    );
                }

                settings.setProxy(proxyType);
                return true;
            } catch (Exception e) {
                System.out.println("Proxy setup failed: " + e.getMessage());
                return false;
            }
        }
        return true;
    }

    private static boolean testProxyConnection(String host, int port) {
        try {
            Socket socket = new Socket();
            socket.connect(new InetSocketAddress(host, port), 5000);
            socket.close();
            return true;
        } catch (Exception e) {
            System.out.println("Proxy test failed: " + e.getMessage());
            return false;
        }
    }

    private static void handleReconnectWithDelay() {
        if (reconnectAttempts.incrementAndGet() <= MAX_RECONNECT_ATTEMPTS) {
            System.out.println("Attempting to reconnect... Attempt " + reconnectAttempts.get() + " of " + MAX_RECONNECT_ATTEMPTS);
            // Добавляем случайную задержку перед переподключением
            long delay = 5000 + random.nextInt(5000);
            scheduler.schedule(() -> {
                System.out.println("Reconnection scheduled...");
            }, delay, TimeUnit.MILLISECONDS);
        } else {
            System.out.println("Max reconnection attempts reached!");
        }
    }

    private static Properties loadConfig() {
        Properties config = new Properties();
        Path configPath = Paths.get("telegram_config.properties");
        
        if (Files.exists(configPath)) {
            try (InputStream input = Files.newInputStream(configPath)) {
                config.load(input);
            } catch (IOException e) {
                System.out.println("Warning: Could not load config file: " + e.getMessage());
            }
        } else {
            // Создаем конфигурацию по умолчанию
            try (OutputStream output = Files.newOutputStream(configPath)) {
                config.setProperty("api.id", "App api_id:");
                config.setProperty("api.hash", "App api_hash:");
                config.setProperty("tdata.path", "D:\\tdatafiles");
                config.setProperty("phone.number", "+12345678901");
                config.setProperty("password.2fa", "your_2fa_password");
                config.setProperty("proxy.enabled", "true");
                config.setProperty("proxy.host", "your_proxy_host");
                config.setProperty("proxy.port", "1080");
                config.setProperty("proxy.username", "proxy_username");
                config.setProperty("proxy.password", "proxy_password");
                config.store(output, "Telegram Client Configuration");
            } catch (IOException e) {
                System.out.println("Warning: Could not create config file: " + e.getMessage());
            }
        }
        return config;
    }

    private static void handleReconnect() {
        if (reconnectAttempts.incrementAndGet() <= MAX_RECONNECT_ATTEMPTS) {
            System.out.println("Attempting to reconnect... Attempt " + reconnectAttempts.get() + " of " + MAX_RECONNECT_ATTEMPTS);
            scheduler.schedule(() -> {
                // Здесь можно добавить дополнительную логику переподключения
                System.out.println("Reconnection scheduled...");
            }, 5, TimeUnit.SECONDS);
        } else {
            System.out.println("Max reconnection attempts reached!");
        }
    }

    private static void handleAuthorizationTimeout() {
        System.out.println("Timeout waiting for authorization");
        if (needPhoneNumber) {
            System.out.println("Error: Phone number verification required - tdata files might not be loaded correctly");
            System.out.println("Check the following:");
            System.out.println("1. All tdata files are present");
            System.out.println("2. Files have correct permissions");
            System.out.println("3. No antivirus blocking access");
            System.out.println("4. Proxy settings are correct");
        }
        if (needCode) {
            System.out.println("Error: Code verification required - tdata files might not be loaded correctly");
        }
        if (need2FA) {
            System.out.println("Error: 2FA password required");
        }
    }

    private static void getUserInfo(SimpleTelegramClient client) throws Exception {
        int attempts = 0;
        while (attempts < 3) {
            try {
                if (!isConnected.get()) {
                    System.out.println("Warning: Not connected to Telegram servers");
                    Thread.sleep(2000);
                    attempts++;
                    continue;
                }

                TdApi.User user = (TdApi.User) client.send(new TdApi.GetMe()).get(10, TimeUnit.SECONDS);
                System.out.println("Logged in as: " + user.firstName + " " + user.lastName);
                System.out.println("User ID: " + user.id);
                System.out.println("Phone: " + user.phoneNumber);

                TdApi.Sessions sessions = (TdApi.Sessions) client.send(new TdApi.GetActiveSessions()).get(10, TimeUnit.SECONDS);
                System.out.println("Active sessions: " + sessions.sessions.length);
                
                TdApi.ConnectionState connectionState = (TdApi.ConnectionState) client.send(new TdApi.GetConnectionState()).get(10, TimeUnit.SECONDS);
                System.out.println("Connection state: " + connectionState.getClass().getSimpleName());
                
                break;
            } catch (Exception e) {
                System.out.println("Attempt " + (attempts + 1) + " failed: " + e.getMessage());
                if (++attempts >= 3) throw e;
                Thread.sleep(2000);
            }
        }
    }

    private static void startHealthCheck(SimpleTelegramClient client) {
        scheduler.scheduleAtFixedRate(() -> {
            try {
                if (isConnected.get()) {
                    TdApi.ConnectionState state = (TdApi.ConnectionState) client.send(new TdApi.GetConnectionState()).get(5, TimeUnit.SECONDS);
                    System.out.println("Health check - Connection state: " + state.getClass().getSimpleName());
                }
            } catch (Exception e) {
                System.out.println("Health check failed: " + e.getMessage());
            }
        }, 0, 30, TimeUnit.SECONDS);
    }

    private static void shutdown(SimpleTelegramClient client) {
        System.out.println("Shutting down client...");
        try {
            scheduler.shutdown();
            scheduler.awaitTermination(5, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            System.out.println("Shutdown interrupted: " + e.getMessage());
        }
        client.close();
        System.out.println("Client shut down successfully");
    }

    private static void validateTDataStructure(Path tdataPath) {
        try {
            // Проверяем основные директории
            Path tdDir = tdataPath.resolve("td");
            Path keyDataDir = tdataPath.resolve("key_datas");
            Path filesDir = tdataPath.resolve("files");
            Path downloadsDir = tdataPath.resolve("downloads");

            // Создаем недостающие директории
            if (!Files.exists(tdDir)) {
                System.out.println("Warning: 'td' directory not found!");
            }
            if (!Files.exists(keyDataDir)) {
                System.out.println("Warning: 'key_datas' directory not found!");
            }
            if (!Files.exists(filesDir)) {
                Files.createDirectories(filesDir);
            }
            if (!Files.exists(downloadsDir)) {
                Files.createDirectories(downloadsDir);
            }

            // Проверяем права доступа
            if (!Files.isReadable(tdataPath)) {
                System.out.println("Warning: Cannot read tdata directory!");
            }
            if (!Files.isWritable(tdataPath)) {
                System.out.println("Warning: Cannot write to tdata directory!");
            }

            // Проверяем наличие ключевых файлов
            if (Files.exists(tdDir)) {
                try (DirectoryStream<Path> stream = Files.newDirectoryStream(tdDir)) {
                    boolean hasFiles = stream.iterator().hasNext();
                    if (!hasFiles) {
                        System.out.println("Warning: 'td' directory is empty!");
                    }
                }
            }

            // Проверяем права на файлы
            if (Files.exists(tdDir)) {
                try (DirectoryStream<Path> stream = Files.newDirectoryStream(tdDir)) {
                    for (Path file : stream) {
                        if (!Files.isReadable(file)) {
                            System.out.println("Warning: Cannot read file: " + file);
                        }
                        if (!Files.isWritable(file)) {
                            System.out.println("Warning: Cannot write to file: " + file);
                        }
                    }
                }
            }

        } catch (Exception e) {
            System.out.println("Error validating tdata structure: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void addAntiBanHandler(SimpleTelegramClient client) {
        // Обработчик для мониторинга подозрительной активности
        scheduler.scheduleAtFixedRate(() -> {
            try {
                if (isConnected.get()) {
                    // Проверяем статус сессии
                    TdApi.Sessions sessions = (TdApi.Sessions) client.send(new TdApi.GetActiveSessions()).get(5, TimeUnit.SECONDS);
                    
                    // Если слишком много сессий, закрываем некоторые
                    if (sessions.sessions.length > 2) {
                        System.out.println("Warning: Too many active sessions detected. Closing older sessions...");
                        for (int i = 2; i < sessions.sessions.length; i++) {
                            try {
                                client.send(new TdApi.TerminateSession(sessions.sessions[i].id));
                                Thread.sleep(1000); // Задержка между закрытием сесс��й
                            } catch (Exception e) {
                                System.out.println("Error closing session: " + e.getMessage());
                            }
                        }
                    }
                }
            } catch (Exception e) {
                System.out.println("Anti-ban check failed: " + e.getMessage());
            }
        }, 1, 5, TimeUnit.MINUTES);
    }

    private static boolean isProxyCountrySafe(Properties config) {
        String proxyCountry = config.getProperty("proxy.country", "").toUpperCase();
        // Проверяем наличие страны в списке безопасных
        for (String country : SAFE_COUNTRIES) {
            if (country.equals(proxyCountry)) {
                // Выводим информацию о регионе прокси
                if (isCISCountry(proxyCountry)) {
                    System.out.println("Using CIS proxy with standard delay");
                } else if (isEUCountry(proxyCountry)) {
                    System.out.println("Using European proxy with increased delay");
                } else if (isUSCountry(proxyCountry)) {
                    System.out.println("Using US/CA proxy with maximum delay");
                }
                return true;
            }
        }
        System.out.println("Warning: Unknown proxy region. Using maximum security measures.");
        return false;
    }

    private static void applyRegionalDelay(String country) throws InterruptedException {
        if (isCISCountry(country)) {
            Thread.sleep(CIS_DELAY + random.nextInt(1000));
        } else if (isEUCountry(country)) {
            Thread.sleep(EU_DELAY + random.nextInt(2000));
        } else if (isUSCountry(country)) {
            Thread.sleep(US_DELAY + random.nextInt(3000));
        }
    }

    private static boolean isCISCountry(String country) {
        return Arrays.asList("RU", "KZ", "BY", "AM", "KG").contains(country);
    }

    private static boolean isEUCountry(String country) {
        return Arrays.asList("DE", "NL", "FR", "GB", "IT", "ES", "SE", "NO", "FI", "DK",
                            "AT", "CH", "BE", "IE", "PL", "CZ", "SK", "HU", "RO", "BG").contains(country);
    }

    private static boolean isUSCountry(String country) {
        return Arrays.asList("US", "CA").contains(country);
    }

    private static boolean isHighSecurityCountry(String country) {
        return Arrays.asList(DELAYED_COUNTRIES).contains(country);
    }
} 