#include "MainWindow.h"
#include "ui_MainWindow.h"

#include <QApplication>
#include <QSystemTrayIcon>
#include <QMenu>
#include <QCloseEvent>
#include <QProcess>
#include <QFileDialog>
#include <QMessageBox>
#include <QDebug>
#include <QDateTime>
#include <algorithm> // For std::reverse
#include <QStandardPaths>
#include <QDir>
#include <QTabWidget>
#include <QSplitter>
#include <QLabel>
#include <QListWidget>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QJsonDocument> // For JSON handling
#include <QJsonObject>   // For JSON objects
#include <QJsonArray>    // For JSON arrays
#include <QFile>         // For file operations
#include <QDesktopServices> // For opening files
#include <QUrl>             // For opening files
#include <QMetaType>
#include <QHostInfo>
#include <QSysInfo>
#include <QTextStream>

// ****************************************************************************
// MainWindow()
// ****************************************************************************
MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
    , clamscanProcess(nullptr)
    , trayIcon(nullptr)
    , trayMenu(nullptr)
    , scanSchedulerTimer(nullptr)
    , updateSchedulerTimer(nullptr)
    , settings(nullptr)
    , versionCheckProcess(nullptr)
    , m_recursiveScanEnabled(false)
    , m_heuristicAlertsEnabled(false)
    , m_encryptedDocumentsAlertsEnabled(false)
    , m_logFile(nullptr)
    , m_scheduledRecursiveScanEnabled(false)
    , m_scheduledHeuristicAlertsEnabled(false)
    , m_scheduledEncryptedDocumentsAlertsEnabled(false)
    , m_scheduledScanArchivesEnabled(false)
    , m_scheduledBellOnVirusEnabled(false)
    , m_scheduledMoveInfectedEnabled(false)
    , m_scheduledRemoveInfectedEnabled(false)
    , appVersionLabel(nullptr)
    , clamavVersionLabel(nullptr)
    , signatureVersionLabel(nullptr)
    , scanStatusLed(nullptr)
    , smtpClient(nullptr) // Initialize smtpClient
    , m_versionCheckIntervalLineEdit(nullptr)
{
    ui->setupUi(this);
    setWindowTitle(QString("Calamity %1.%2-%3").arg(APP_VERSION).arg(GIT_COMMIT_COUNT).arg(GIT_HASH));
    setStyleSheet(
        "QMainWindow, QWidget, QFrame { background-color: #FADA5E; }"); // Set background color to Naples' yellow for main window and panels

    // Initialize LED pixmaps
    ledGreenPixmap = QPixmap(":/icons/led_green.png");
    ledGrayPixmap = QPixmap(":/icons/led_gray.png");

    // Initialize scanStatusLed and add to status bar
    scanStatusLed = new QLabel(this);
    scanStatusLed->setFixedSize(16, 16); // Set fixed size for the LED
    scanStatusLed->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
    scanStatusLed->setPixmap(ledGrayPixmap); // Initial state: grayed out
    ui->statusbar->addPermanentWidget(scanStatusLed);

    // Initialize QProcess
    clamscanProcess = new QProcess(this);
    versionCheckProcess = new QProcess(this);
    m_onlineVersionCheckProcess = new QProcess(this);

    // Connect QProcess signals to slots
    connect(clamscanProcess, &QProcess::readyReadStandardOutput, this, &MainWindow::readClamscanOutput);
    connect(clamscanProcess, &QProcess::readyReadStandardError, this, &MainWindow::readClamscanOutput);
    connect(clamscanProcess, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished), this, &MainWindow::clamscanFinished);
    connect(clamscanProcess, &QProcess::errorOccurred, this, &MainWindow::clamscanErrorOccurred);
    connect(m_onlineVersionCheckProcess, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished), this, &MainWindow::onOnlineVersionCheckFinished);

    // Connect LED status updates
    connect(ui->scanButton, &QPushButton::clicked, this, [this]() { updateScanStatusLed(true); });
    connect(ui->stopButton, &QPushButton::clicked, this, [this]() { updateScanStatusLed(false); });
    connect(clamscanProcess, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished), this, [this](int, QProcess::ExitStatus) { updateScanStatusLed(false); });
    connect(clamscanProcess, &QProcess::errorOccurred, this, [this](QProcess::ProcessError) { updateScanStatusLed(false); });

    // Connect UI signals to slots
    connect(ui->scanButton, &QPushButton::clicked, this, &MainWindow::scanButton_clicked);
    connect(ui->browseButton, &QPushButton::clicked, this, &MainWindow::browseButton_clicked);
    connect(ui->stopButton, &QPushButton::clicked, this, &MainWindow::stopButton_clicked);
    connect(ui->clearOutputButton, &QPushButton::clicked, this, &MainWindow::clearOutputButton_clicked);
    connect(ui->moveInfectedCheckBox, &QCheckBox::toggled, this, &MainWindow::moveInfectedCheckBox_toggled);
    connect(ui->clearHistoryButton, &QPushButton::clicked, this, &MainWindow::clearHistoryButtonClicked);
    connect(ui->openLastReportButton, &QPushButton::clicked, this, &MainWindow::openLastReportButtonClicked);
    connect(ui->openReportsFolderButton,
            &QPushButton::clicked,
            this,
            &MainWindow::openScanReportFolderButtonClicked);
    connect(ui->browseQuarantineButton, &QPushButton::clicked, this, &MainWindow::browseQuarantineButtonClicked);
    connect(ui->browseScheduledScanPathButton, &QPushButton::clicked, this, &MainWindow::browseScheduledScanPathButtonClicked);
    connect(ui->recursiveScanCheckBox, &QCheckBox::toggled, this, &MainWindow::recursiveScanCheckBox_toggled);
    connect(ui->heuristicAlertsCheckBox, &QCheckBox::toggled, this, &MainWindow::heuristicAlertsCheckBox_toggled);
    connect(ui->encryptedDocumentsAlertsCheckBox, &QCheckBox::toggled, this, &MainWindow::encryptedDocumentsAlertsCheckBox_toggled);
    connect(ui->detectPuaCheckBox, &QCheckBox::toggled, this, &MainWindow::detectPuaCheckBox_toggled);
    connect(ui->scheduledRecursiveScanCheckBox, &QCheckBox::toggled, this, &MainWindow::scheduledRecursiveScanCheckBox_toggled);
    connect(ui->scheduledHeuristicAlertsCheckBox, &QCheckBox::toggled, this, &MainWindow::scheduledHeuristicAlertsCheckBox_toggled);
    connect(ui->scheduledEncryptedDocumentsAlertsCheckBox, &QCheckBox::toggled, this, &MainWindow::scheduledEncryptedDocumentsAlertsCheckBox_toggled);
    connect(ui->scheduledDetectPuaCheckBox, &QCheckBox::toggled, this, &MainWindow::scheduledDetectPuaCheckBox_toggled);
    connect(ui->scheduledScanArchivesCheckBox, &QCheckBox::toggled, this, &MainWindow::scheduledScanArchivesCheckBox_toggled);
    
    connect(ui->scheduledMoveInfectedCheckBox, &QCheckBox::toggled, this, &MainWindow::scheduledMoveInfectedCheckBox_toggled);
    connect(ui->scheduledRemoveInfectedCheckBox, &QCheckBox::toggled, this, &MainWindow::scheduledRemoveInfectedCheckBox_toggled);
    connect(ui->browseScheduledQuarantineButton, &QPushButton::clicked, this, &MainWindow::browseScheduledQuarantineButtonClicked);

    // Connect scheduling UI signals to slots
    connect(ui->saveScanScheduleButton, &QPushButton::clicked, this, &MainWindow::saveScanScheduleButtonClicked);
    connect(ui->saveUpdateScheduleButton, &QPushButton::clicked, this, &MainWindow::saveUpdateScheduleButtonClicked);
    connect(ui->updateNowButton,
            &QPushButton::clicked,
            this,
            &MainWindow::updateNowButtonClicked);
    connect(ui->refreshVersionsButton, &QPushButton::clicked, this, &MainWindow::refreshVersionsButtonClicked);

    // Connect exclusion UI signals to slots
    connect(ui->addExclusionButton, &QPushButton::clicked, this, &MainWindow::handleAddExclusionButtonClicked);
    connect(ui->removeExclusionButton, &QPushButton::clicked, this, &MainWindow::handleRemoveExclusionButtonClicked);
    connect(ui->browseExclusionButton, &QPushButton::clicked, this, &MainWindow::browseExclusionButtonClicked);

    // Connect scan history table double click
    connect(ui->scanHistoryTable, &QTableWidget::cellDoubleClicked, this, &MainWindow::on_scanHistoryTable_cellDoubleClicked);
    connect(ui->openLastUpdateReportButton, &QPushButton::clicked, this, &MainWindow::openLastUpdateReportButtonClicked);
    connect(ui->openUpdateReportsFolderButton, &QPushButton::clicked, this, &MainWindow::openUpdateReportsFolderButtonClicked);
    connect(ui->updateHistoryTable, &QTableWidget::cellDoubleClicked, this, &MainWindow::on_updateHistoryTable_cellDoubleClicked);
    connect(ui->refreshUpdateHistoryButton, &QPushButton::clicked, this, &MainWindow::refreshUpdateHistoryButtonClicked);

    connect(ui->clearUpdatesHistoryButton, &QPushButton::clicked, this, &MainWindow::clearUpdatesHistoryButtonClicked);

    // Connect fileDropped signal from custom QTextEdit
    connect(ui->outputLog, &ScanOutputTextEdit::fileDropped, this, &MainWindow::handleFileDropped);

    // Connect email settings signals to slots
    connect(ui->emailReportCheckBox, &QCheckBox::toggled, this, &MainWindow::onEmailReportCheckBox_toggled);
    connect(ui->saveEmailSettingsButton, &QPushButton::clicked, this, &MainWindow::onSaveEmailSettingsButton_clicked);
    connect(ui->testEmailButton, &QPushButton::clicked, this, &MainWindow::onTestEmailButton_clicked);

    m_updateCheckProcess = new QProcess(this);
    connect(m_updateCheckProcess, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished), this, &MainWindow::onVersionCheckFinished);
    checkForUpdates();

    m_versionCheckTimer = new QTimer(this);
    connect(m_versionCheckTimer, &QTimer::timeout, this, &MainWindow::onVersionCheckTimerTimeout);

    m_updateVersionTimer = new QTimer(this);
    connect(m_updateVersionTimer, &QTimer::timeout, this, &MainWindow::updateVersionInfo);

    // Connect versionCheckIntervalLineEdit to slot
    m_versionCheckIntervalLineEdit = ui->versionCheckIntervalLineEdit;
    connect(m_versionCheckIntervalLineEdit, &QLineEdit::editingFinished, this, &MainWindow::onVersionCheckIntervalLineEditChanged);

    // Connect new status page button
    connect(ui->openStatusPageButton, &QPushButton::clicked, this, &MainWindow::openStatusPageButtonClicked);

    // Connect ASAP update checkbox
    connect(ui->asapUpdateCheckBox, &QCheckBox::stateChanged, this, &MainWindow::on_asapUpdateCheckBox_stateChanged);

    // Initial UI state
    ui->stopButton->setEnabled(false);
    ui->quarantinePathLineEdit->setEnabled(false); // Disable quarantine path initially
    updateStatusBar("Ready");

    createTrayIcon();

    // Setup and load scheduling
    scanSchedulerTimer = new QTimer(this);
    updateSchedulerTimer = new QTimer(this);

    // Set up QSettings to save to ~/.calamity/settings.ini
    QString settingsDirPath = QStandardPaths::writableLocation(QStandardPaths::HomeLocation)
                              + "/.calamity";
    QDir settingsDir(settingsDirPath);
    if (!settingsDir.exists()) {
        settingsDir.mkpath("."); // Create the directory if it doesn't exist
    }
    settings = new QSettings(settingsDirPath + "/settings.ini", QSettings::IniFormat, this);

    connect(scanSchedulerTimer, &QTimer::timeout, this, &MainWindow::scanSchedulerTimerTimeout);
    connect(updateSchedulerTimer, &QTimer::timeout, this, &MainWindow::updateSchedulerTimerTimeout);

    loadScheduleSettings();
    setupSchedulers();
    loadUiSettings(); // Load UI settings on startup
    loadEmailSettings(); // Load email settings on startup
    m_versionCheckTimer->start(m_fullVersionCheckInterval * 60 * 1000); // Start full check timer
    m_updateVersionTimer->start(m_versionCheckInterval * 60 * 1000); // Start timer with loaded value
    moveInfectedCheckBox_toggled(ui->moveInfectedCheckBox->isChecked()); // Update quarantine path line edit state based on loaded setting
    loadExclusionSettings(); // Load exclusion settings on startup
    loadScanHistory(); // Load scan history on startup

    // Initialize QLabel pointers (assuming they exist in .ui file)
    appVersionLabel = ui->appVersionLabel;
    clamavVersionLabel = ui->clamavVersionLabel;
    signatureVersionLabel = ui->signatureVersionLabel;

    updateVersionInfo(); // Update version info on startup

    // Setup scan history table headers
    ui->scanHistoryTable->setColumnCount(4);
    ui->scanHistoryTable->setHorizontalHeaderLabels(QStringList() << "Timestamp" << "Scanned Path" << "Status" << "Threats Found");
    ui->scanHistoryTable->horizontalHeader()->setStretchLastSection(true);
    ui->scanHistoryTable->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    ui->scanHistoryTable->horizontalHeader()->setVisible(true); // Ensure header is visible
    ui->scanHistoryTable->verticalHeader()->setVisible(true); // Ensure vertical header is visible
    // Set a default minimum width for columns to ensure visibility
    for (int i = 0; i < ui->scanHistoryTable->columnCount(); ++i) {
        ui->scanHistoryTable->setColumnWidth(i, 100); // Set a default width, will be adjusted by ResizeToContents
    }
    displayScanHistory(); // Display history on startup

    // Setup update history table headers
    ui->updateHistoryTable->setColumnCount(2);
    ui->updateHistoryTable->setHorizontalHeaderLabels(QStringList() << "Timestamp" << "Status");
    ui->updateHistoryTable->horizontalHeader()->setStretchLastSection(true);
    populateUpdateHistoryTable();
}
// ****************************************************************************
// Helpers: multi-path parsing and display
// ****************************************************************************
QStringList MainWindow::parsePathsText(const QString &text) const
{
    QString normalized = text;
    // Allow semicolons and newlines as separators
    normalized.replace('\n', ';');
    normalized.remove('\r');
    QStringList parts = normalized.split(';', Qt::SkipEmptyParts);
    QStringList paths;
    for (QString part : parts) {
        QString trimmed = part.trimmed();
        if (!trimmed.isEmpty()) {
            paths << trimmed;
        }
    }
    return paths;
}

QString MainWindow::joinPathsForDisplay(const QStringList &paths) const
{
    return paths.join("; ");
}

void MainWindow::appendPathToLineEdit(QLineEdit *lineEdit, const QString &path)
{
    if (!lineEdit) return;
    QStringList current = parsePathsText(lineEdit->text());
    if (!current.contains(path)) {
        current << path;
    }
    lineEdit->setText(joinPathsForDisplay(current));
}

// ****************************************************************************
// ~MainWindow()
// ****************************************************************************
MainWindow::~MainWindow()
{
    saveUiSettings(); // Save UI settings before closing
    saveExclusionSettings(); // Save exclusion settings before closing
    saveScanHistory(); // Save scan history before closing
    if (clamscanProcess->state() == QProcess::Running) {
        clamscanProcess->terminate();
        clamscanProcess->waitForFinished(1000); // Give it some time to terminate
    }
    delete clamscanProcess;
    delete ui;
    if (trayIcon) {
        trayIcon->hide();
        delete trayIcon;
    }
    if (trayMenu) {
        delete trayMenu;
    }
    // QTimers and QSettings are parented to this, so they will be deleted automatically
    // versionCheckProcess is also parented to this
}

// ****************************************************************************
// createTrayIcon()
// ****************************************************************************
void MainWindow::createTrayIcon()
{
    trayIcon = new QSystemTrayIcon(this);
    trayMenu = new QMenu(this);

    QAction *scanAction = new QAction(tr("Scan Now"), this);
    connect(scanAction, &QAction::triggered, this, &MainWindow::scanActionTriggered);
    trayMenu->addAction(scanAction);

    QAction *showHideAction = new QAction(tr("Show / Hide"), this);
    connect(showHideAction, &QAction::triggered, this, &MainWindow::showHideActionTriggered);
    trayMenu->addAction(showHideAction);

    QAction *openStatusPageAction = new QAction(tr("Open Status Page"), this);
    connect(openStatusPageAction, &QAction::triggered, this, &MainWindow::openStatusPageButtonClicked);
    trayMenu->addAction(openStatusPageAction);

    trayMenu->addSeparator();

    QAction *quitAction = new QAction(tr("Quit"), this);
    connect(quitAction, &QAction::triggered, this, &MainWindow::quitActionTriggered);
    trayMenu->addAction(quitAction);

    trayIcon->setContextMenu(trayMenu);
    trayIcon->setIcon(QIcon(":/icons/app_icon.png")); // You need to add an icon resource
    trayIcon->setToolTip(
        QString("Calamity %1.%2-%3").arg(APP_VERSION).arg(GIT_COMMIT_COUNT).arg(GIT_HASH));

    connect(trayIcon, &QSystemTrayIcon::activated, this, &MainWindow::trayIconActivated);

    trayIcon->show();
}

// ****************************************************************************
// closeEvent()
// ****************************************************************************
void MainWindow::closeEvent(QCloseEvent *event)
{
    saveUiSettings(); // Save UI settings before closing
    saveExclusionSettings(); // Save exclusion settings before closing
    saveScanHistory(); // Save scan history before closing
    saveEmailSettings(); // Save email settings before closing
    if (trayIcon->isVisible()) {
        hide();
        event->ignore();
    } else {
        event->accept();
    }
}

// ****************************************************************************
// trayIconActivated()
// ****************************************************************************
void MainWindow::trayIconActivated(QSystemTrayIcon::ActivationReason reason)
{
    if (reason == QSystemTrayIcon::Trigger || reason == QSystemTrayIcon::DoubleClick) {
        // Restore the window if it's hidden, otherwise hide it
        if (this->isHidden()) {
            this->showNormal();
            this->raise();
            this->activateWindow();
        } else {
            this->hide();
        }
    }
}

// ****************************************************************************
// showHideActionTriggered()
// ****************************************************************************
void MainWindow::showHideActionTriggered()
{
    if (this->isHidden()) {
        this->showNormal();
        this->raise();
        this->activateWindow();
    } else {
        this->hide();
    }
}

// ****************************************************************************
// quitActionTriggered()
// ****************************************************************************
void MainWindow::quitActionTriggered()
{
    QApplication::quit();
}

// ****************************************************************************
// scanActionTriggered()
// ****************************************************************************
void MainWindow::scanActionTriggered()
{
    scanButton_clicked(); // Reuse the existing scan logic
}

// ****************************************************************************
// browseButton_clicked()
// ****************************************************************************
void MainWindow::browseButton_clicked()
{
    QString path = QFileDialog::getExistingDirectory(this, tr("Select Directory to Scan"),
                                                 QDir::homePath(),
                                                 QFileDialog::ShowDirsOnly | QFileDialog::DontResolveSymlinks);
    if (path.isEmpty()) {
        path = QFileDialog::getOpenFileName(this, tr("Select File to Scan"),
                                            QDir::homePath());
    }

    if (!path.isEmpty()) {
        appendPathToLineEdit(ui->pathLineEdit, path);
    }
}

// ****************************************************************************
// scanButton_clicked()
// ****************************************************************************
void MainWindow::scanButton_clicked()
{
    qDebug() << "scanButton_clicked() called.";
    QStringList pathsToScan = parsePathsText(ui->pathLineEdit->text());
    qDebug() << "Paths to scan from pathLineEdit:" << pathsToScan;
    if (pathsToScan.isEmpty()) {
        QMessageBox::warning(this, tr("Input Error"), tr("Please select a file or directory to scan."));
        return;
    }

    if (clamscanProcess->state() == QProcess::Running) {
        QMessageBox::information(this, tr("Scan in Progress"), tr("A scan is already running. Please wait or stop the current scan."));
        return;
    }

    // Create a temporary file to store the scan log
    m_logFile = new QTemporaryFile(this);
    if (!m_logFile->open()) {
        QMessageBox::critical(this, tr("File Error"), tr("Failed to create temporary log file."));
        delete m_logFile;
        m_logFile = nullptr;
        return;
    }

    ui->outputLog->clear();
    m_lastScanTargetsDisplay = joinPathsForDisplay(pathsToScan);
    m_scanStartedAt = QDateTime::currentDateTime();
    m_scanTimer.restart();
    ui->outputLog
        ->append(QString("Scan of '%1' started at %2").arg(m_lastScanTargetsDisplay, QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss")));
    updateStatusBar("Scan in progress...");
    updateScanStatusLed(true); // Explicitly set LED to green when scan starts
    ui->scanButton->setEnabled(false);
    ui->stopButton->setEnabled(true);

    QStringList arguments = buildClamscanArguments();
    arguments << pathsToScan; // Add all paths to scan as the last arguments

    qDebug() << "Executing clamscan with arguments:" << arguments;

    QString command = "clamscan";
    if (ui->sudoCheckBox->isChecked()) {
        command = "sudo";
        arguments.prepend("clamscan");
    }

    // Save last invocation for report
    m_lastCommand = command;
    m_lastArguments = arguments;

    clamscanProcess->start(command, arguments);

    if (!clamscanProcess->waitForStarted()) {
        QMessageBox::critical(this, tr("Process Error"), tr("Failed to start clamscan process. Make sure clamscan is in your system's PATH."));
        updateStatusBar("Error: Could not start clamscan.");
        ui->scanButton->setEnabled(true);
        ui->stopButton->setEnabled(false);
    }
}

// ****************************************************************************
// stopButton_clicked()
// ****************************************************************************
void MainWindow::stopButton_clicked()
{
    if (m_logFile) {
        m_logFile->close();
        delete m_logFile;
        m_logFile = nullptr;
    }
    if (clamscanProcess->state() == QProcess::Running) {
        clamscanProcess->terminate(); // Try to terminate gracefully
        if (!clamscanProcess->waitForFinished(3000)) { // Wait up to 3 seconds
            clamscanProcess->kill(); // Force kill if not terminated
        }
        updateStatusBar("Scan stopped by user.");
    }
    ui->scanButton->setEnabled(true);
    ui->stopButton->setEnabled(false);
}

// ****************************************************************************
// clearOutputButton_clicked()
// ****************************************************************************
void MainWindow::clearOutputButton_clicked()
{
    ui->outputLog->clear();
    updateStatusBar("Output cleared.");
}

// ****************************************************************************
// moveInfectedCheckBox_toggled()
// ****************************************************************************
void MainWindow::moveInfectedCheckBox_toggled(bool checked)
{
    ui->quarantinePathLineEdit->setEnabled(checked);
}

// ****************************************************************************
// readClamscanOutput()
// ****************************************************************************
void MainWindow::readClamscanOutput()
{
    QString output = clamscanProcess->readAllStandardOutput();
    if (!output.isEmpty() && m_logFile) {
        m_logFile->write(output.toUtf8());
    }
    ui->outputLog->append(output.trimmed());

    QString errorOutput = clamscanProcess->readAllStandardError();
    if (!errorOutput.isEmpty() && m_logFile) {
        m_logFile->write(errorOutput.toUtf8());
    }
    ui->outputLog->append(errorOutput.trimmed());
}

// ****************************************************************************
// clamscanFinished()
// ****************************************************************************
void MainWindow::clamscanFinished(int exitCode, QProcess::ExitStatus exitStatus)
{
    Q_UNUSED(exitStatus); // Not using exitStatus directly, but keeping for signature

    if (m_lastCommand.contains("freshclam") || m_lastArguments.contains("freshclam")) {
        if (m_logFile) {
            m_logFile->seek(0);
            QByteArray logData = m_logFile->readAll();
            m_logFile->close();
            delete m_logFile;
            m_logFile = nullptr;
            generateUpdateReport(logData);
        }
        updateStatusBar("Update finished.");
        return;
    }

    int numThreats = 0;
    QStringList threatDetails;

    if (m_logFile) {
        m_logFile->seek(0);
        QByteArray logData = m_logFile->readAll();
        m_logFile->close();
        delete m_logFile;
        m_logFile = nullptr;

        if (!logData.isEmpty()) {
            // Parse threats from log
            QString logString = QString::fromLatin1(logData);
            QRegularExpression threatLineRx("^(.*):\\s+(.*)\\s+FOUND");
            for (const QString& line : logString.split('\n', Qt::SkipEmptyParts)) {
                QString trimmedLine = line.trimmed();
                QRegularExpressionMatch match = threatLineRx.match(trimmedLine);
                if (match.hasMatch()) {
                    QString filePath = match.captured(1);
                    QString threatName = match.captured(2);
                    QString searchUrl = QString("https://www.google.com/search?q=%1")
                                            .arg(QString(QUrl::toPercentEncoding(threatName)));
                    threatDetails << QString("<tr><td>%1</td><td>%2</td><td><a href=\" %3 \" target=\"_blank\">More info</a></td></tr>")
                                     .arg(filePath.toHtmlEscaped(), threatName.toHtmlEscaped(), searchUrl);
                }
            }
            numThreats = threatDetails.size();

            // Build HTML report
            QString reportPath = QDir::tempPath() + "/report.html";
            QFile reportFile(reportPath);
            if (reportFile.open(QIODevice::WriteOnly | QIODevice::Text)) {
                // Collect environment info
                QString hostname = QHostInfo::localHostName();
                QString kernel = QSysInfo::prettyProductName() + " (" + QSysInfo::kernelType() + " " + QSysInfo::kernelVersion() + ")";
                qint64 elapsedMs = m_scanTimer.isValid() ? m_scanTimer.elapsed() : 0;

                // Extract options
                QStringList opts;
                for (const QString &arg : m_lastArguments) {
                    if (arg.startsWith('-')) opts << arg;
                }
                const auto hasOpt = [&](const QString &opt){ return m_lastArguments.contains(opt); };
                const bool usedSudo = (m_lastCommand == "sudo");
                bool recursive = hasOpt("--recursive");
                bool heuristic = hasOpt("--heuristic-alerts");
                bool scanArchives = hasOpt("--scan-archive");
                bool detectPua = hasOpt("--detect-pua=yes");
                
                bool removeInf = hasOpt("--remove");
                QString quarantinePath;
                for (const QString &arg : m_lastArguments) {
                    if (arg.startsWith("--move=")) { quarantinePath = arg.mid(QString("--move=").size()); break; }
                }
                QString alertEncrypted = hasOpt("--alert-encrypted=yes") ? "yes" : (hasOpt("--alert-encrypted=no") ? "no" : "(unspecified)");

                // Optional embedded logo as data URI
                QString logoTag;
                {
                    QFile logo(":/icons/app_icon_64x64.png");
                    if (logo.open(QIODevice::ReadOnly)) {
                        const QByteArray logoData = logo.readAll();
                        const QString base64 = QString::fromLatin1(logoData.toBase64());
                        logoTag = QString("<img src=\"data:image/png;base64,%1\" alt=\"Calamity\" style=\"width:64px;height:64px;vertical-align:middle;margin-right:10px;\"/>").arg(base64);
                    }
                }

                // Build simple HTML
                QString html;
                html += "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>Calamity Scan Report</title>";
                html += "<style>body{font-family:sans-serif;background:#FADA5E;color:#111}h1{margin-bottom:0}small{color:#555}table{border-collapse:collapse;margin:10px 0}td,th{border:1px solid #ccc;padding:6px 8px;text-align:left}code,pre{background:#f7f7f9;border:1px solid #e1e1e8;padding:8px;display:block;white-space:pre-wrap;}</style></head><body>";
                
                if (!logoTag.isEmpty()) {
                    html += "<div style=\"display:flex;align-items:center;gap:10px;\">" + logoTag + "<div>";
                    html += "<h1>Calamity Scan Report</h1>";
                    html += QString("<small>Generated: %1</small>").arg(QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss"));
                    html += "</div></div>";
                } else {
                    html += "<h1>Calamity Scan Report</h1>";
                    html += QString("<small>Generated: %1</small>").arg(QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss"));
                }

                // --- Customisation : add result status ---
                QString statusMessage;
                QString statusIcon;
                if (exitCode == 0) {
                    statusMessage = "No threats found";
                    QFile iconFile(":/icons/led_green.png");
                    if (iconFile.open(QIODevice::ReadOnly)) {
                        statusIcon = QString("<img src=\"data:image/png;base64,%1\" style=\"width:32px;height:32px;vertical-align:middle;margin-right:10px;\"/>").arg(QString::fromLatin1(iconFile.readAll().toBase64()));
                    }
                } else {
                    statusMessage = "Threats found!";
                    QFile iconFile(":/icons/led_red.png");
                    if (iconFile.open(QIODevice::ReadOnly)) {
                        statusIcon = QString("<img src=\"data:image/png;base64,%1\" style=\"width:32px;height:32px;vertical-align:middle;margin-right:10px;\"/>").arg(QString::fromLatin1(iconFile.readAll().toBase64()));
                    }
                }
                html += "<div style=\"display:flex;align-items:center;gap:10px;padding:10px;border:1px solid #ccc;border-radius:5px;margin-top:20px;margin-bottom:20px;\">";
                html += statusIcon;
                html += "<div><h2 style=\"margin:0;font-size:24px;\">" + statusMessage + "</h2>";
                if (numThreats > 0) {
                    html += QString("<p style=\"margin:0;font-size:14px;\">%1 threat(s) found.</p>").arg(numThreats);
                }
                html += "</div></div>";
                // ---

                html += "<h2>Summary</h2><table>";
                html += QString("<tr><th>Targets</th><td>%1</td></tr>").arg(m_lastScanTargetsDisplay.toHtmlEscaped());
                html += QString("<tr><th>Command</th><td><code>%1 %2</code></td></tr>").arg(m_lastCommand.toHtmlEscaped(), m_lastArguments.join(' ').toHtmlEscaped());
                // html += QString("<tr><th>Options</th><td><code>%1</code></td></tr>").arg(opts.join(' ').toHtmlEscaped());
                html += QString("<tr><th>Application</th><td>Calamity %1.%2-%3</td></tr>").arg(APP_VERSION).arg(GIT_COMMIT_COUNT).arg(GIT_HASH);
                if (!m_clamavVersion.isEmpty()) {
                    html += QString("<tr><th>ClamAV Engine</th><td>%1</td></tr>").arg(m_clamavVersion.toHtmlEscaped());
                }
                if (!m_signatureVersionInfo.isEmpty()) {
                    html += QString("<tr><th>Signatures</th><td>%1</td></tr>").arg(m_signatureVersionInfo.toHtmlEscaped());
                }
                html += QString("<tr><th>Hostname</th><td>%1</td></tr>").arg(hostname.toHtmlEscaped());
                html += QString("<tr><th>OS/Kernel</th><td>%1</td></tr>").arg(kernel.toHtmlEscaped());
                html += QString("<tr><th>Started</th><td>%1</td></tr>").arg(m_scanStartedAt.toString("yyyy-MM-dd hh:mm:ss"));
                html += QString("<tr><th>Ended</th><td>%1</td></tr>")
                            .arg(QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss"));
                html += QString("<tr><th>Elapsed</th><td>%1</td></tr>")
                            .arg(timeConversion(elapsedMs));
                html += "</table>";

                html += "<h2>Settings</h2><table>";
                html += QString("<tr><th>Sudo</th><td>%1</td></tr>").arg(usedSudo ? "yes" : "no");
                html += QString("<tr><th>Recursive</th><td>%1</td></tr>").arg(recursive ? "yes" : "no");
                html += QString("<tr><th>Heuristic Alerts</th><td>%1</td></tr>").arg(heuristic ? "yes" : "no");
                html += QString("<tr><th>Detect PUA</th><td>%1</td></tr>").arg(detectPua ? "yes" : "no");
                html += QString("<tr><th>Encrypted Alerts</th><td>%1</td></tr>").arg(alertEncrypted.toHtmlEscaped());
                html += QString("<tr><th>Scan Archives</th><td>%1</td></tr>").arg(scanArchives ? "yes" : "no");
                
                html += QString("<tr><th>Remove Infected</th><td>%1</td></tr>").arg(removeInf ? "yes" : "no");
                html += QString("<tr><th>Move Infected</th><td>%1</td></tr>").arg(quarantinePath.isEmpty() ? "no" : "yes");
                if (!quarantinePath.isEmpty()) html += QString("<tr><th>Quarantine Path</th><td>%1</td></tr>").arg(quarantinePath.toHtmlEscaped());
                html += QString("<tr><th>Exclusions</th><td>%1</td></tr>").arg(exclusionPaths.isEmpty() ? "(none)" : exclusionPaths.join("; ").toHtmlEscaped());
                html += "</table>";

                if (numThreats > 0) {
                    html += "<h2>Threats Found</h2><table>";
                    html += "<tr><th>File Path</th><th>Threat Name</th><th>Details</th></tr>";
                    html += threatDetails.join("");
                    html += "</table>";
                }

                html += "<h2>Raw Output</h2><pre>" + QString::fromUtf8(logData).toHtmlEscaped() + "</pre>";
                html += "</body></html>";

                QTextStream out(&reportFile);
                out.setCodec("UTF-8");
                out << html;
                reportFile.close();

                QString scansDirPath = QStandardPaths::writableLocation(QStandardPaths::HomeLocation) + "/.calamity/reports/scans";
                QDir scansDir(scansDirPath);
                if (!scansDir.exists()) {
                    scansDir.mkpath(".");
                }

                QString timestamp = QDateTime::currentDateTime().toString("yyyy-MM-dd_hh-mm-ss");
                QString reportFileName = QString("%1.html").arg(timestamp);
                QString reportFilePath = scansDirPath + "/" + reportFileName;

                if (reportFile.copy(reportFilePath)) {
                    qDebug() << "Scan log saved to:" << reportFilePath;
                    m_lastReportPath = reportFilePath;
                } else {
                    qWarning() << "Could not save scan log to:" << reportFilePath;
                }

                reportFile.remove();
            } else {
                qWarning() << "Could not create temporary report file:" << reportPath;
            }
        }
    }

    QString statusMessage;
    QString scanStatus;

    if (exitCode == 0) {
        statusMessage = "Scan finished: No threats found.";
        scanStatus = "Clean";
        trayIcon->showMessage("Calamity",
                              tr("Scan finished.\nNo threats found.\nReport: %1").arg(m_lastReportPath),
                              QSystemTrayIcon::Information,
                              4000);
    } else if (exitCode == 1) {
        statusMessage = "Scan finished: Threats found!";
        scanStatus = "Threats Found";
        trayIcon->showMessage("Calamity",
                              tr("Scan finished.\nThreats found: %1\nReport: %2").arg(numThreats).arg(m_lastReportPath),
                              QSystemTrayIcon::Critical,
                              4000);
    } else if (exitCode == 2) {
        statusMessage = "Scan finished: Error occurred.";
        scanStatus = "Error";
        trayIcon->showMessage("Calamity",
                              tr("Scan finished.\nError occured."),
                              QSystemTrayIcon::Warning,
                              2000);
    } else {
        statusMessage = QString("Scan finished with exit code: %1").arg(exitCode);
        scanStatus = "Unknown Error";
        trayIcon->showMessage("Calamity",
                              tr("Scan finished.\nUnknown error."),
                              QSystemTrayIcon::Warning,
                              2000);
    }
    updateStatusBar(statusMessage);

    // Add to scan history
    QString scannedPath = m_lastScanTargetsDisplay.isEmpty() ? joinPathsForDisplay(parsePathsText(ui->pathLineEdit->text())) : m_lastScanTargetsDisplay;
    qDebug() << "Paths from pathLineEdit in clamscanFinished:" << scannedPath;
    addScanResult(scannedPath, scanStatus, numThreats);

    generateStatusPage();

    ui->scanButton->setEnabled(true);
    ui->stopButton->setEnabled(false);
}




// ****************************************************************************
// clamscanErrorOccurred()
// ****************************************************************************
void MainWindow::clamscanErrorOccurred(QProcess::ProcessError error)
{
    if (m_logFile) {
        m_logFile->close();
        delete m_logFile;
        m_logFile = nullptr;
    }
    QString errorMessage;
    switch (error) {
    case QProcess::FailedToStart:
        errorMessage = "Failed to start clamscan. Check if it's installed and in PATH.";
        break;
    case QProcess::Crashed:
        errorMessage = "Clamscan process crashed.";
        break;
    case QProcess::Timedout:
        errorMessage = "Clamscan process timed out.";
        break;
    case QProcess::ReadError:
        errorMessage = "Error reading from clamscan process.";
        break;
    case QProcess::WriteError:
        errorMessage = "Error writing to clamscan process.";
        break;
    case QProcess::UnknownError:
    default:
        errorMessage = "An unknown error occurred with clamscan process.";
        break;
    }
    QMessageBox::critical(this, tr("Clamscan Process Error"), errorMessage);
    updateStatusBar("Error: " + errorMessage);

    // Add to scan history as an error
    addScanResult(ui->pathLineEdit->text(), "Error", 0);

    ui->scanButton->setEnabled(true);
    ui->stopButton->setEnabled(false);
}

// ****************************************************************************
// updateStatusBar()
// ****************************************************************************
void MainWindow::updateStatusBar(const QString &message)
{
    ui->statusbar->showMessage(message, 3000);
}

// ****************************************************************************
// buildClamscanArguments()
// ****************************************************************************
QStringList MainWindow::buildClamscanArguments()
{
    QStringList arguments;

    // Add common arguments for better output
    arguments << "--stdout" << "-i"; // Ensure output goes to stdout and report only infected files

    if (ui->scanArchivesCheckBox->isChecked()) {
        arguments << "--scan-archive";
    }
    if (ui->moveInfectedCheckBox->isChecked()) {
        QString quarantinePath = ui->quarantinePathLineEdit->text();
        if (!quarantinePath.isEmpty()) {
            arguments << "--move=" + quarantinePath;
        } else {
            QMessageBox::warning(this, tr("Quarantine Path Missing"), tr("Please specify a quarantine path for moving infected files."));
            // Do not add --move argument if path is empty, and uncheck the box
            ui->moveInfectedCheckBox->setChecked(false); 
        }
    }
    if (ui->removeInfectedCheckBox->isChecked()) {
        arguments << "--remove";
    }
    

    // Add new scan options
    if (ui->recursiveScanCheckBox->isChecked()) {
        arguments << "--recursive";
    }
    if (ui->heuristicAlertsCheckBox->isChecked()) {
        arguments << "--heuristic-alerts";
    }
    if (ui->encryptedDocumentsAlertsCheckBox->isChecked()) {
        arguments << "--alert-encrypted=yes";
    } else {
        arguments << "--alert-encrypted=no";
    }

    if (ui->detectPuaCheckBox->isChecked()) {
        arguments << "--detect-pua=yes";
    }

    // Add exclusion paths
    for (const QString &path : qAsConst(exclusionPaths)) {
        arguments << "--exclude=" + path;
    }

    return arguments;
}

// ****************************************************************************
// browseQuarantineButtonClicked()
// ****************************************************************************
void MainWindow::browseQuarantineButtonClicked()
{
    QString path = QFileDialog::getExistingDirectory(this, tr("Select Quarantine Directory"),
                                                 QDir::homePath(),
                                                 QFileDialog::ShowDirsOnly | QFileDialog::DontResolveSymlinks);
    if (!path.isEmpty()) {
        ui->quarantinePathLineEdit->setText(path);
    }
}

// ****************************************************************************
// browseScheduledScanPathButtonClicked()
// ****************************************************************************
void MainWindow::browseScheduledScanPathButtonClicked()
{
    QString path = QFileDialog::getExistingDirectory(this, tr("Select Directory to Scan"),
                                                 QDir::homePath(),
                                                 QFileDialog::ShowDirsOnly | QFileDialog::DontResolveSymlinks);
    if (!path.isEmpty()) {
        appendPathToLineEdit(ui->scheduledScanPathLineEdit, path);
    }
}

// ****************************************************************************
// openLastReportButtonClicked()
// ****************************************************************************
void MainWindow::openLastReportButtonClicked()
{
    QString scansDirPath = QStandardPaths::writableLocation(QStandardPaths::HomeLocation) + "/.calamity/reports/scans";
    QDir dir(scansDirPath);
    if (!dir.exists()) {
        QMessageBox::information(this, tr("No Reports"), tr("No scan reports directory found."));
        return;
    }
    QStringList filters;
    filters << "*.zip";
    QFileInfoList list = dir.entryInfoList(filters, QDir::Files | QDir::NoSymLinks, QDir::Time | QDir::Reversed);
    if (list.isEmpty()) {
        QMessageBox::information(this, tr("No Reports"), tr("No scan reports found."));
        return;
    }
    // Take the newest
    QFileInfo newest = list.last();
    QDesktopServices::openUrl(QUrl::fromLocalFile(newest.absoluteFilePath()));
}

// ****************************************************************************
// openReportsFolderButtonClicked()
// ****************************************************************************
void MainWindow::openReportsFolderButtonClicked()
{
    QString scansDirPath = QStandardPaths::writableLocation(QStandardPaths::HomeLocation)
                           + "/.calamity/reports";
    QDir dir(scansDirPath);
    if (!dir.exists()) {
        QMessageBox::information(this, tr("No Reports"), tr("No scan reports directory found."));
        return;
    }
    QDesktopServices::openUrl(QUrl::fromLocalFile(scansDirPath));
}

// ****************************************************************************
// openScanReportFolderButtonClicked()
// ****************************************************************************
void MainWindow::openScanReportFolderButtonClicked()
{
    QString scansDirPath = QStandardPaths::writableLocation(QStandardPaths::HomeLocation) + "/.calamity/reports/scans";
    QDir dir(scansDirPath);
    if (!dir.exists()) {
        QMessageBox::information(this, tr("No Reports"), tr("No scan reports directory found."));
        return;
    }
    QDesktopServices::openUrl(QUrl::fromLocalFile(scansDirPath));
}

// ****************************************************************************
// openLastUpdateReportButtonClicked()
// ****************************************************************************
void MainWindow::openLastUpdateReportButtonClicked()
{
    QString scansDirPath = QStandardPaths::writableLocation(QStandardPaths::HomeLocation)
                           + "/.calamity/reports/updates";
    QDir dir(scansDirPath);
    if (!dir.exists()) {
        QMessageBox::information(this, tr("No Reports"), tr("No update reports directory found."));
        return;
    }
    QStringList filters;
    filters << "*.zip";
    QFileInfoList list = dir.entryInfoList(filters,
                                           QDir::Files | QDir::NoSymLinks,
                                           QDir::Time | QDir::Reversed);
    if (list.isEmpty()) {
        QMessageBox::information(this, tr("No Reports"), tr("No update reports found."));
        return;
    }
    // Take the newest
    QFileInfo newest = list.last();
    QDesktopServices::openUrl(QUrl::fromLocalFile(newest.absoluteFilePath()));
}

// ****************************************************************************
// openUpdateReportsFolderButtonClicked()
// ****************************************************************************
void MainWindow::openUpdateReportsFolderButtonClicked()
{
    QString updatesDirPath = QStandardPaths::writableLocation(QStandardPaths::HomeLocation) + "/.calamity/reports/updates";
    QDir dir(updatesDirPath);
    if (!dir.exists()) {
        QMessageBox::information(this, tr("No Reports"), tr("No update reports directory found."));
        return;
    }
    QDesktopServices::openUrl(QUrl::fromLocalFile(updatesDirPath));
}

// ****************************************************************************
// openStatusPageButtonClicked()
// ****************************************************************************
void MainWindow::openStatusPageButtonClicked()
{
    QString statusFilePath = QStandardPaths::writableLocation(QStandardPaths::HomeLocation) + "/.calamity/reports/status.html";
    if (QFile::exists(statusFilePath)) {
        QDesktopServices::openUrl(QUrl::fromLocalFile(statusFilePath));
    } else {
        QMessageBox::information(this, tr("Status Page Not Found"), tr("The status page could not be found. Please run a scan or update to generate it."));
    }
}

// ****************************************************************************
// populateUpdateHistoryTable()
// ****************************************************************************
void MainWindow::populateUpdateHistoryTable()
{
    ui->updateHistoryTable->setRowCount(0);
    QString updatesDirPath = QStandardPaths::writableLocation(QStandardPaths::HomeLocation) + "/.calamity/reports/updates";
    QDir dir(updatesDirPath);
    if (!dir.exists()) {
        return;
    }

    QStringList filters;
    filters << "*.zip";
    QFileInfoList list = dir.entryInfoList(filters, QDir::Files | QDir::NoSymLinks, QDir::Time);

    for (const QFileInfo &fileInfo : list) {
        int row = ui->updateHistoryTable->rowCount();
        ui->updateHistoryTable->insertRow(row);
        QDateTime timestamp = QDateTime::fromString(fileInfo.baseName(), "yyyy-MM-dd_hh-mm-ss");
        ui->updateHistoryTable->setItem(row, 0, new QTableWidgetItem(timestamp.toString("yyyy-MM-dd hh:mm:ss")));
        ui->updateHistoryTable->setItem(row, 1, new QTableWidgetItem("Success")); // Assuming success for now
    }
}

// ****************************************************************************
// on_updateHistoryTable_cellDoubleClicked()
// ****************************************************************************
void MainWindow::on_updateHistoryTable_cellDoubleClicked(int row, int column)
{
    Q_UNUSED(column);
    QTableWidgetItem *item = ui->updateHistoryTable->item(row, 0);
    if (!item) return;

    QDateTime timestamp = QDateTime::fromString(item->text(), "yyyy-MM-dd hh:mm:ss");
    QString fileName = timestamp.toString("yyyy-MM-dd_hh-mm-ss") + ".zip";
    QString reportPath = QStandardPaths::writableLocation(QStandardPaths::HomeLocation) + "/.calamity/reports/updates/" + fileName;

    if (QFile::exists(reportPath)) {
        QDesktopServices::openUrl(QUrl::fromLocalFile(reportPath));
    } else {
        QMessageBox::warning(this, tr("File Not Found"), tr("The report file could not be found."));
    }
}

// ****************************************************************************
// refreshUpdateHistoryButtonClicked()
// ****************************************************************************
void MainWindow::refreshUpdateHistoryButtonClicked()
{
    populateUpdateHistoryTable();
}

// ****************************************************************************
// New Scan Option Slots
// ****************************************************************************
void MainWindow::recursiveScanCheckBox_toggled(bool checked)
{
    m_recursiveScanEnabled = checked;
}

void MainWindow::heuristicAlertsCheckBox_toggled(bool checked)
{
    m_heuristicAlertsEnabled = checked;
}

void MainWindow::encryptedDocumentsAlertsCheckBox_toggled(bool checked)
{
    m_encryptedDocumentsAlertsEnabled = checked;
}

void MainWindow::detectPuaCheckBox_toggled(bool checked)
{
    m_detectPuaEnabled = checked;
}



// ****************************************************************************
// setupSchedulers()
// ****************************************************************************
void MainWindow::setupSchedulers()
{
    // This function will be called after loading settings to set up timers
    startScanScheduler();
    startUpdateScheduler();
}

// ****************************************************************************
// loadScheduleSettings()
// ****************************************************************************
void MainWindow::loadScheduleSettings()
{
    // Scan Schedule
    ui->enableScanScheduleCheckBox->setChecked(settings->value("ScanSchedule/Enabled", false).toBool());
    ui->scanFrequencyComboBox->setCurrentText(settings->value("ScanSchedule/Frequency", "Daily").toString());
    ui->scanTimeEdit->setTime(settings->value("ScanSchedule/Time", QTime(3, 0)).toTime());
    // Backward compatibility: accept single string or string list
    QVariant scheduledPathVar = settings->value("ScanSchedule/Path", QDir::homePath());
    QStringList scheduledPaths = scheduledPathVar.toStringList();
    if (!scheduledPaths.isEmpty()) {
        ui->scheduledScanPathLineEdit->setText(joinPathsForDisplay(scheduledPaths));
    } else {
        ui->scheduledScanPathLineEdit->setText(scheduledPathVar.toString());
    }
    ui->scheduledScanSudoCheckBox->setChecked(settings->value("ScanSchedule/Sudo", false).toBool());
    ui->scheduledRecursiveScanCheckBox->setChecked(settings->value("ScanSchedule/RecursiveScan", false).toBool());
    ui->scheduledHeuristicAlertsCheckBox->setChecked(settings->value("ScanSchedule/HeuristicAlerts", false).toBool());
    ui->scheduledEncryptedDocumentsAlertsCheckBox->setChecked(settings->value("ScanSchedule/EncryptedDocumentsAlerts", false).toBool());
    ui->scheduledDetectPuaCheckBox->setChecked(settings->value("ScanSchedule/DetectPua", false).toBool());
    ui->scheduledScanArchivesCheckBox->setChecked(settings->value("ScanSchedule/ScanArchives", false).toBool());
    
    ui->scheduledMoveInfectedCheckBox->setChecked(settings->value("ScanSchedule/MoveInfected", false).toBool());
    ui->scheduledQuarantinePathLineEdit->setText(settings->value("ScanSchedule/QuarantinePath", "").toString());
    ui->scheduledRemoveInfectedCheckBox->setChecked(settings->value("ScanSchedule/RemoveInfected", false).toBool());

    // Update Schedule
    ui->enableUpdateScheduleCheckBox->setChecked(settings->value("UpdateSchedule/Enabled", false).toBool());
    ui->updateFrequencyComboBox->setCurrentText(settings->value("UpdateSchedule/Frequency", "Daily").toString());
    ui->updateTimeEdit->setTime(settings->value("UpdateSchedule/Time", QTime(4, 0)).toTime());
    ui->scheduledUpdateSudoCheckBox->setChecked(settings->value("UpdateSchedule/Sudo", false).toBool());
}

// ****************************************************************************
// saveScheduleSettings()
// ****************************************************************************
void MainWindow::saveScheduleSettings()
{
    // Scan Schedule
    settings->setValue("ScanSchedule/Enabled", ui->enableScanScheduleCheckBox->isChecked());
    settings->setValue("ScanSchedule/Frequency", ui->scanFrequencyComboBox->currentText());
    settings->setValue("ScanSchedule/Time", ui->scanTimeEdit->time());
    settings->setValue("ScanSchedule/Path", parsePathsText(ui->scheduledScanPathLineEdit->text()));
    settings->setValue("ScanSchedule/Sudo", ui->scheduledScanSudoCheckBox->isChecked());
    settings->setValue("ScanSchedule/RecursiveScan", ui->scheduledRecursiveScanCheckBox->isChecked());
    settings->setValue("ScanSchedule/HeuristicAlerts", ui->scheduledHeuristicAlertsCheckBox->isChecked());
    settings->setValue("ScanSchedule/EncryptedDocumentsAlerts", ui->scheduledEncryptedDocumentsAlertsCheckBox->isChecked());
    settings->setValue("ScanSchedule/DetectPua", ui->scheduledDetectPuaCheckBox->isChecked());
    settings->setValue("ScanSchedule/ScanArchives", ui->scheduledScanArchivesCheckBox->isChecked());
    
    settings->setValue("ScanSchedule/MoveInfected", ui->scheduledMoveInfectedCheckBox->isChecked());
    settings->setValue("ScanSchedule/QuarantinePath", ui->scheduledQuarantinePathLineEdit->text());
    settings->setValue("ScanSchedule/RemoveInfected", ui->scheduledRemoveInfectedCheckBox->isChecked());

    // Update Schedule
    settings->setValue("UpdateSchedule/Enabled", ui->enableUpdateScheduleCheckBox->isChecked());
    settings->setValue("UpdateSchedule/Frequency", ui->updateFrequencyComboBox->currentText());
    settings->setValue("UpdateSchedule/Time", ui->updateTimeEdit->time());
    settings->setValue("UpdateSchedule/Sudo", ui->scheduledUpdateSudoCheckBox->isChecked());

    settings->sync(); // Ensure settings are written to disk
    updateStatusBar("Schedule settings saved.");
}

// ****************************************************************************
// startScanScheduler()
// ****************************************************************************
void MainWindow::startScanScheduler()
{
    scanSchedulerTimer->stop();
    if (ui->enableScanScheduleCheckBox->isChecked()) {
        QDateTime now = QDateTime::currentDateTime();
        QTime scheduledTime = ui->scanTimeEdit->time();
        QDateTime nextRun = QDateTime(now.date(), scheduledTime);

        if (nextRun < now) {
            // If the scheduled time for today has passed, schedule for tomorrow
            nextRun = nextRun.addDays(1);
        }

        qint64 msecToWait = now.msecsTo(nextRun);
        scanSchedulerTimer->setInterval(msecToWait); // Initial wait until the first scheduled time
        scanSchedulerTimer->setSingleShot(true);
        scanSchedulerTimer->start();
        qDebug() << "Scan scheduled to run at:" << nextRun;
        updateStatusBar(QString("Next scan scheduled for: %1").arg(nextRun.toString()));
        ui->lblNextScanScheduled->setText(nextRun.toString());
    }
}

// ****************************************************************************
// startUpdateScheduler()
// ****************************************************************************
void MainWindow::startUpdateScheduler()
{
    updateSchedulerTimer->stop();
    if (ui->asapUpdateCheckBox->isChecked()) {
        ui->lblNextUpdateScheduled->setText(tr("ASAP +/- %1 minutes").arg(ui->versionCheckIntervalLineEdit->text()));
        return;
    }
    if (ui->enableUpdateScheduleCheckBox->isChecked()) {
        QDateTime now = QDateTime::currentDateTime();
        QTime scheduledTime = ui->updateTimeEdit->time();
        QDateTime nextRun = QDateTime(now.date(), scheduledTime);

        if (nextRun < now) {
            // If the scheduled time for today has passed, schedule for tomorrow
            nextRun = nextRun.addDays(1);
        }

        qint64 msecToWait = now.msecsTo(nextRun);
        updateSchedulerTimer->setInterval(msecToWait); // Initial wait until the first scheduled time
        updateSchedulerTimer->setSingleShot(true);
        updateSchedulerTimer->start();
        qDebug() << "Update scheduled to run at:" << nextRun;
        updateStatusBar(QString("Next update scheduled for: %1").arg(nextRun.toString()));
        ui->lblNextUpdateScheduled->setText(nextRun.toString());
    }
}

// ****************************************************************************
// runScheduledScan()
// ****************************************************************************
void MainWindow::runScheduledScan()
{
    QStringList pathsToScan = parsePathsText(ui->scheduledScanPathLineEdit->text());
    if (pathsToScan.isEmpty()) {
        qWarning() << "Scheduled scan path is empty. Skipping scan.";
        updateStatusBar("Scheduled scan skipped: No path specified.");
        return;
    }

    if (clamscanProcess->state() == QProcess::Running) {
        qWarning() << "A scan is already running. Skipping scheduled scan.";
        updateStatusBar("Scheduled scan skipped: Another scan in progress.");
        return;
    }

    // Create a temporary file to store the scan log
    m_logFile = new QTemporaryFile(this);
    if (!m_logFile->open()) {
        QMessageBox::critical(this, tr("File Error"), tr("Failed to create temporary log file."));
        delete m_logFile;
        m_logFile = nullptr;
        return;
    }

    ui->outputLog->clear();
    m_scanStartedAt = QDateTime::currentDateTime();
    m_scanTimer.restart();
    ui->outputLog->append("Scheduled scan (" + joinPathsForDisplay(pathsToScan) + ") started at "
                          + m_scanStartedAt.toString("yyyy-MM-dd hh:mm:ss"));
    updateStatusBar("Scheduled scan in progress...");
    updateScanStatusLed(true);
    QStringList arguments;
    // arguments << "--stdout" << "--no-summary";
    arguments << "--stdout" << "-i"; // Report only infected files
    // Add other desired clamscan options for scheduled scans here
    if (ui->scheduledRecursiveScanCheckBox->isChecked()) {
        arguments << "--recursive";
    }
    if (ui->scheduledHeuristicAlertsCheckBox->isChecked()) {
        arguments << "--heuristic-alerts";
    }
    if (ui->scheduledEncryptedDocumentsAlertsCheckBox->isChecked()) {
        arguments << "--alert-encrypted=yes";
    } else {
        arguments << "--alert-encrypted=no";
    }
    if (ui->scheduledDetectPuaCheckBox->isChecked()) {
        arguments << "--detect-pua=yes";
    }
    if (ui->scheduledScanArchivesCheckBox->isChecked()) {
        arguments << "--scan-archive";
    }
    
    if (ui->scheduledMoveInfectedCheckBox->isChecked()) {
        QString quarantinePath = ui->scheduledQuarantinePathLineEdit->text();
        if (!quarantinePath.isEmpty()) {
            arguments << "--move=" + quarantinePath;
        } else {
            qWarning() << "Scheduled scan: Quarantine path is empty, skipping --move.";
        }
    }
    if (ui->scheduledRemoveInfectedCheckBox->isChecked()) {
        arguments << "--remove";
    }
    arguments << pathsToScan;
    m_lastScanTargetsDisplay = joinPathsForDisplay(pathsToScan);

    qDebug() << "Executing scheduled clamscan with arguments:" << arguments;
    QString command = "clamscan";
    if (ui->scheduledScanSudoCheckBox->isChecked()) {
        command = "sudo";
        arguments.prepend("clamscan");
    }
    // Save last invocation for report
    m_lastCommand = command;
    m_lastArguments = arguments;
    clamscanProcess->start(command, arguments);

    // After the first run, set the timer for the next day/week/month
    // For simplicity, this example assumes daily. More complex logic needed for weekly/monthly.
    scanSchedulerTimer->setInterval(24 * 60 * 60 * 1000); // Reschedule for next day
    scanSchedulerTimer->setSingleShot(false); // Make it repeating
    scanSchedulerTimer->start();

    // Update information for next run
    QDateTime nextRun = QDateTime(QDateTime::currentDateTime());
    nextRun = nextRun.addMSecs(scanSchedulerTimer->interval());
    ui->lblNextScanScheduled->setText(nextRun.toString());
}

// ****************************************************************************
// runScheduledUpdate()
// ****************************************************************************
void MainWindow::runScheduledUpdate()
{
    if (clamscanProcess->state() == QProcess::Running) {
        qWarning() << "A scan is running. Skipping scheduled update.";
        updateStatusBar("Scheduled update skipped: Scan in progress.");
        return;
    }

    // Create a temporary file to store the scan log
    m_logFile = new QTemporaryFile(this);
    if (!m_logFile->open()) {
        QMessageBox::critical(this, tr("File Error"), tr("Failed to create temporary log file."));
        delete m_logFile;
        m_logFile = nullptr;
        return;
    }

    m_updateTimer.start(); // Start the update timer
    m_updateStartedAt = QDateTime::currentDateTime(); // Record update start time

    ui->outputLog->clear();
    updateStatusBar("Scheduled update started...");

    QStringList arguments;
    // Add any specific freshclam arguments if needed

    qDebug() << "Executing scheduled freshclam.";
    // Note: freshclam usually runs as a daemon or requires specific permissions.
    // Running it directly from the GUI might require elevated privileges.
    QString command = "freshclam";
    if (ui->scheduledUpdateSudoCheckBox->isChecked()) {
        command = "sudo";
        arguments.prepend("freshclam");
    }

    // Save last invocation for report
    m_lastCommand = command;
    m_lastArguments = arguments;

    clamscanProcess->start(command, arguments);

    // After the first run, set the timer for the next day/week
    // For simplicity, this example assumes daily. More complex logic needed for weekly.
    updateSchedulerTimer->setInterval(24 * 60 * 60 * 1000); // Reschedule for next day
    updateSchedulerTimer->setSingleShot(false); // Make it repeating
    updateSchedulerTimer->start();

    // Update information for next run
    QDateTime nextRun = QDateTime(QDateTime::currentDateTime());
    nextRun = nextRun.addMSecs(updateSchedulerTimer->interval());
    ui->lblNextUpdateScheduled->setText(nextRun.toString());
}

// ****************************************************************************
// saveScanScheduleButtonClicked()
// ****************************************************************************
void MainWindow::saveScanScheduleButtonClicked()
{
    saveScheduleSettings();
    startScanScheduler();
}

// ****************************************************************************
// saveUpdateScheduleButtonClicked()
// ****************************************************************************
void MainWindow::saveUpdateScheduleButtonClicked()
{
    saveScheduleSettings();
    startUpdateScheduler();
}

// ****************************************************************************
// scanSchedulerTimerTimeout()
// ****************************************************************************
void MainWindow::scanSchedulerTimerTimeout()
{
    runScheduledScan();
}

// ****************************************************************************
// updateSchedulerTimerTimeout()
// ****************************************************************************
void MainWindow::updateSchedulerTimerTimeout()
{
    runScheduledUpdate();
}

// ****************************************************************************
// refreshVersionsButtonClicked()
// ****************************************************************************
void MainWindow::refreshVersionsButtonClicked()
{
    updateVersionInfo();
}

// ****************************************************************************
// updateNowButtonClicked()
// ****************************************************************************
void MainWindow::updateNowButtonClicked()
{
    if (clamscanProcess->state() == QProcess::Running) {
        qWarning() << "A scan is running. Skipping update.";
        updateStatusBar("Update skipped: Scan in progress.");
        return;
    }

    // Create a temporary file to store the update log
    m_logFile = new QTemporaryFile(this);
    if (!m_logFile->open()) {
        QMessageBox::critical(this, tr("File Error"), tr("Failed to create temporary log file."));
        delete m_logFile;
        m_logFile = nullptr;
        return;
    }

    m_updateTimer.start(); // Start the update timer
    m_updateStartedAt = QDateTime::currentDateTime(); // Record update start time

    ui->outputLog->clear();
    updateStatusBar("Update started...");

    QStringList arguments;
    // Add any specific freshclam arguments if needed

    qDebug() << "Executing freshclam.";
    // Note: freshclam usually runs as a daemon or requires specific permissions.
    // Running it directly from the GUI might require elevated privileges.
    QString command = "freshclam";
    if (ui->scheduledUpdateSudoCheckBox->isChecked()) {
        command = "sudo";
        arguments.prepend("freshclam");
    }

    // Save last invocation for report
    m_lastCommand = command;
    m_lastArguments = arguments;

    clamscanProcess->start(command, arguments);
}

// ****************************************************************************
// browseExclusionButtonClicked()
// ****************************************************************************
void MainWindow::browseExclusionButtonClicked()
{
    QString path = QFileDialog::getExistingDirectory(this, tr("Select Directory to Exclude"),
                                                 QDir::homePath(),
                                                 QFileDialog::ShowDirsOnly | QFileDialog::DontResolveSymlinks);
    if (path.isEmpty()) {
        path = QFileDialog::getOpenFileName(this, tr("Select File to Exclude"),
                                            QDir::homePath());
    }

    if (!path.isEmpty()) {
        ui->newExclusionPathLineEdit->setText(path);
    }
}

// ****************************************************************************
// handleAddExclusionButtonClicked()
// ****************************************************************************
void MainWindow::handleAddExclusionButtonClicked()
{
    QString newPath = ui->newExclusionPathLineEdit->text().trimmed();
    if (!newPath.isEmpty() && !exclusionPaths.contains(newPath)) {
        exclusionPaths.append(newPath);
        ui->exclusionListWidget->addItem(newPath);
        ui->newExclusionPathLineEdit->clear();
        saveExclusionSettings(); // Save immediately after adding
        updateStatusBar(tr("Exclusion added: %1").arg(newPath));
    } else if (newPath.isEmpty()) {
        QMessageBox::warning(this, tr("Input Error"), tr("Please enter a path to exclude."));
    } else {
        QMessageBox::information(this, tr("Duplicate Entry"), tr("This path is already in the exclusion list."));
    }
}

// ****************************************************************************
// handleRemoveExclusionButtonClicked()
// ****************************************************************************
void MainWindow::handleRemoveExclusionButtonClicked()
{
    QListWidgetItem *item = ui->exclusionListWidget->currentItem();
    if (item) {
        QString pathToRemove = item->text();
        exclusionPaths.removeOne(pathToRemove);
        delete ui->exclusionListWidget->takeItem(ui->exclusionListWidget->row(item));
        saveExclusionSettings(); // Save immediately after removing
        updateStatusBar(tr("Exclusion removed: %1").arg(pathToRemove));
    } else {
        QMessageBox::warning(this, tr("Selection Error"), tr("Please select an item to remove from the exclusion list."));
    }
}

// ****************************************************************************
// saveUiSettings()
// ****************************************************************************
void MainWindow::saveUiSettings()
{
    settings->beginGroup("MainWindow");
    settings->setValue("geometry", saveGeometry());
    settings->setValue("windowState", saveState());
    if (ui->tabWidget) {
        settings->setValue("currentTab", ui->tabWidget->currentIndex());
    }
    if (ui->splitter) {
        settings->setValue("splitterSizes", ui->splitter->saveState());
    }
    settings->endGroup();

    // Save Manual Scan Settings
    settings->beginGroup("ManualScan");
    settings->setValue("path", parsePathsText(ui->pathLineEdit->text()));
    settings->setValue("scanArchives", ui->scanArchivesCheckBox->isChecked());
    settings->setValue("moveInfected", ui->moveInfectedCheckBox->isChecked());
    settings->setValue("quarantinePath", ui->quarantinePathLineEdit->text());
    settings->setValue("removeInfected", ui->removeInfectedCheckBox->isChecked());
    
    settings->setValue("sudo", ui->sudoCheckBox->isChecked());
    settings->setValue("recursiveScan", ui->recursiveScanCheckBox->isChecked());
    settings->setValue("heuristicAlerts", ui->heuristicAlertsCheckBox->isChecked());
    settings->setValue("encryptedDocumentsAlerts", ui->encryptedDocumentsAlertsCheckBox->isChecked());
    settings->setValue("detectPua", ui->detectPuaCheckBox->isChecked());
    settings->endGroup();

    settings->beginGroup("General");
    if (m_versionCheckIntervalLineEdit) {
        bool ok;
        int newInterval = m_versionCheckIntervalLineEdit->text().toInt(&ok);
        if (ok && newInterval > 0) {
            m_versionCheckInterval = newInterval;
        }
    }
    settings->setValue("VersionCheckInterval", m_versionCheckInterval);
    settings->setValue("FullVersionCheckInterval", m_fullVersionCheckInterval);
    settings->setValue("AsapUpdate", ui->asapUpdateCheckBox->isChecked());
    settings->endGroup();

    settings->sync();
}

// ****************************************************************************
// loadUiSettings()
// ****************************************************************************
void MainWindow::loadUiSettings()
{
    settings->beginGroup("MainWindow");
    restoreGeometry(settings->value("geometry").toByteArray());
    restoreState(settings->value("windowState").toByteArray());
    if (ui->tabWidget) {
        ui->tabWidget->setCurrentIndex(settings->value("currentTab", 0).toInt());
    }
    if (ui->splitter) {
        ui->splitter->restoreState(settings->value("splitterSizes").toByteArray());
    }
    settings->endGroup();

    // Load Manual Scan Settings
    settings->beginGroup("ManualScan");
    // Backward compatibility: accept single string or string list
    {
        QVariant manualPathVar = settings->value("path", QDir::homePath());
        QStringList manualPaths = manualPathVar.toStringList();
        if (!manualPaths.isEmpty()) {
            ui->pathLineEdit->setText(joinPathsForDisplay(manualPaths));
        } else {
            ui->pathLineEdit->setText(manualPathVar.toString());
        }
    }
    ui->scanArchivesCheckBox->setChecked(settings->value("scanArchives", false).toBool());
    ui->moveInfectedCheckBox->setChecked(settings->value("moveInfected", false).toBool());
    ui->quarantinePathLineEdit->setText(settings->value("quarantinePath", "").toString());
    ui->removeInfectedCheckBox->setChecked(settings->value("removeInfected", false).toBool());
    
    ui->sudoCheckBox->setChecked(settings->value("sudo", false).toBool());
    ui->recursiveScanCheckBox->setChecked(settings->value("recursiveScan", false).toBool());
    ui->heuristicAlertsCheckBox->setChecked(settings->value("heuristicAlerts", false).toBool());
    ui->encryptedDocumentsAlertsCheckBox->setChecked(settings->value("encryptedDocumentsAlerts", false).toBool());
    ui->detectPuaCheckBox->setChecked(settings->value("detectPua", false).toBool());
    settings->endGroup();

    settings->beginGroup("General");
    m_versionCheckInterval = settings->value("VersionCheckInterval", 15).toInt();
    m_fullVersionCheckInterval = settings->value("FullVersionCheckInterval", 1440).toInt();
    if (m_versionCheckIntervalLineEdit) {
        m_versionCheckIntervalLineEdit->setText(QString::number(m_versionCheckInterval));
    }
    ui->asapUpdateCheckBox->setChecked(settings->value("AsapUpdate", false).toBool());
    settings->endGroup();

    settings->sync();
}

// ****************************************************************************
// loadEmailSettings()
// ****************************************************************************
void MainWindow::loadEmailSettings()
{
    settings->beginGroup("Email");
    ui->emailReportCheckBox->setChecked(settings->value("Enabled", false).toBool());
    ui->smtpServerLineEdit->setText(settings->value("SmtpServer", "").toString());
    ui->smtpPortLineEdit->setText(settings->value("SmtpPort", 587).toString()); // Default to 587 for TLS
    ui->smtpUsernameLineEdit->setText(settings->value("SmtpUsername", "").toString());
    ui->smtpPasswordLineEdit->setText(settings->value("SmtpPassword", "").toString());
    ui->recipientLineEdit->setText(settings->value("Recipient", "").toString());
    settings->endGroup();
}

// ****************************************************************************
// saveEmailSettings()
// ****************************************************************************
void MainWindow::saveEmailSettings()
{
    settings->beginGroup("Email");
    settings->setValue("Enabled", ui->emailReportCheckBox->isChecked());
    settings->setValue("SmtpServer", ui->smtpServerLineEdit->text());
    settings->setValue("SmtpPort", ui->smtpPortLineEdit->text().toInt());
    settings->setValue("SmtpUsername", ui->smtpUsernameLineEdit->text());
    settings->setValue("SmtpPassword", ui->smtpPasswordLineEdit->text());
    settings->setValue("Recipient", ui->recipientLineEdit->text());
    settings->endGroup();
    settings->sync();
    updateStatusBar("Email settings saved.");
}

// ****************************************************************************
// loadExclusionSettings()
// ****************************************************************************
void MainWindow::loadExclusionSettings()
{
    exclusionPaths = settings->value("Exclusions/Paths").toStringList();
    ui->exclusionListWidget->clear();
    for (const QString &path : qAsConst(exclusionPaths)) {
        ui->exclusionListWidget->addItem(path);
    }
}

// ****************************************************************************
// saveExclusionSettings()
// ****************************************************************************
void MainWindow::saveExclusionSettings()
{
    settings->setValue("Exclusions/Paths", exclusionPaths);
    settings->sync();
}

// ****************************************************************************
// addScanResult()
// ****************************************************************************
void MainWindow::addScanResult(const QString &path, const QString &status, int threats)
{
    ScanResult result;
    result.timestamp = QDateTime::currentDateTime();
    result.scannedPath = path.isEmpty() ? tr("N/A") : path; // Use "N/A" if path is empty
    result.status = status;
    result.threatsFound = threats;
    scanHistory.append(result);
    qDebug() << "Added scan result:" << result.timestamp << result.scannedPath << result.status << result.threatsFound;
    displayScanHistory(); // Refresh display
}

// ****************************************************************************
// addUpdateResult()
// ****************************************************************************
void MainWindow::addUpdateResult(const QString &status)
{
    UpdateResult result;
    result.timestamp = QDateTime::currentDateTime();
    result.status = status;
    updateHistory.append(result);
    qDebug() << "Added update result:" << result.timestamp << result.status;
    populateUpdateHistoryTable(); // Refresh display
}

// ****************************************************************************
// loadScanHistory()
// ****************************************************************************
void MainWindow::loadScanHistory()
{
    QString historyDirPath = QStandardPaths::writableLocation(QStandardPaths::HomeLocation)
                             + "/.calamity";
    QString historyFilePath = historyDirPath + "/scan_history.json";
    QFile loadFile(historyFilePath);

    if (!loadFile.open(QIODevice::ReadOnly)) {
        qDebug() << "Could not open scan history file for reading:" << historyFilePath;
        return;
    }

    QByteArray saveData = loadFile.readAll();
    QJsonDocument jsonDoc(QJsonDocument::fromJson(saveData));
    loadFile.close();

    if (jsonDoc.isArray()) {
        scanHistory.clear(); // Clear existing history before loading
        QJsonArray jsonArray = jsonDoc.array();
        qDebug() << "Loading" << jsonArray.size() << "scan results from" << historyFilePath;
        for (const QJsonValue &value : jsonArray) {
            QJsonObject obj = value.toObject();
            ScanResult result;
            result.timestamp = QDateTime::fromString(obj["timestamp"].toString(), Qt::ISODate);
            result.scannedPath = obj["scannedPath"].toString();
            if (result.scannedPath.isEmpty()) {
                result.scannedPath = tr("N/A");
            }
            result.status = obj["status"].toString();
            result.threatsFound = obj["threatsFound"].toInt();
            scanHistory.append(result);
            qDebug() << "Loaded:" << result.timestamp << result.scannedPath << result.status << result.threatsFound;
        }
        qDebug() << "Scan history loaded from:" << historyFilePath;
    } else {
        qWarning() << "Scan history file is not a JSON array or is invalid:" << historyFilePath;
    }
}

// ****************************************************************************
// saveScanHistory()
// ****************************************************************************
void MainWindow::saveScanHistory()
{
    QString historyDirPath = QStandardPaths::writableLocation(QStandardPaths::HomeLocation)
                             + "/.calamity";
    QDir historyDir(historyDirPath);
    if (!historyDir.exists()) {
        historyDir.mkpath("."); // Create the directory if it doesn't exist
    }
    QString historyFilePath = historyDirPath + "/scan_history.json";
    QFile saveFile(historyFilePath);

    if (!saveFile.open(QIODevice::WriteOnly)) {
        qWarning() << "Could not open scan history file for writing:" << historyFilePath;
        return;
    }

    QJsonArray jsonArray;
    for (const ScanResult &result : qAsConst(scanHistory)) {
        QJsonObject obj;
        obj["timestamp"] = result.timestamp.toString(Qt::ISODate);
        obj["scannedPath"] = result.scannedPath;
        obj["status"] = result.status;
        obj["threatsFound"] = result.threatsFound;
        jsonArray.append(obj);
    }

    QJsonDocument jsonDoc(jsonArray);
    saveFile.write(jsonDoc.toJson());
    saveFile.close();
    qDebug() << "Scan history saved to:" << historyFilePath;
}

// ****************************************************************************
// displayScanHistory()
// ****************************************************************************
void MainWindow::displayScanHistory()
{
    ui->scanHistoryTable->setRowCount(0); // Clear existing rows
    qDebug() << "Displaying scan history. Number of entries::" << scanHistory.size();
    for (const ScanResult &result : qAsConst(scanHistory)) {
        int row = ui->scanHistoryTable->rowCount();
        ui->scanHistoryTable->insertRow(row);
        ui->scanHistoryTable->setItem(row, 0, new QTableWidgetItem(result.timestamp.toString("yyyy-MM-dd hh:mm:ss")));
        ui->scanHistoryTable->setItem(row, 1, new QTableWidgetItem(result.scannedPath));
        ui->scanHistoryTable->setItem(row, 2, new QTableWidgetItem(result.status));
        QTableWidgetItem *qtwThreats = new QTableWidgetItem(QString::number(result.threatsFound));
        qtwThreats->setTextAlignment(Qt::AlignCenter);
        ui->scanHistoryTable->setItem(row, 3, qtwThreats);

        qDebug() << "Added row:" << result.timestamp.toString("yyyy-MM-dd hh:mm:ss")
                 << result.scannedPath << result.status << result.threatsFound;
    }
    ui->scanHistoryTable->resizeColumnsToContents();
    ui->scanHistoryTable->viewport()->update(); // Force repaint of the viewport
}

// ****************************************************************************
// clearHistoryButtonClicked()
// ****************************************************************************
void MainWindow::clearHistoryButtonClicked()
{
    QMessageBox::StandardButton reply;
    reply = QMessageBox::question(this,
                                  tr("Clear Scan History"),
                                  tr("Are you sure you want to clear all scan history and "
                                     "associated reports ?\nThis action cannot be undone."),
                                  QMessageBox::Yes | QMessageBox::No);
    if (reply == QMessageBox::Yes) {
        // Clear the in-memory history
        scanHistory.clear();
        // Clear the table view
        ui->scanHistoryTable->setRowCount(0);
        // Save the empty history to the JSON file
        saveScanHistory();

        // Delete the report files
        QString scansDirPath = QStandardPaths::writableLocation(QStandardPaths::HomeLocation) + "/.calamity/reports/scans";
        QDir dir(scansDirPath);
        if (dir.exists()) {
            dir.setNameFilters(QStringList() << "*.html");
            dir.setFilter(QDir::Files);
            for(const QString &dirFile : dir.entryList()) {
                dir.remove(dirFile);
            }
        }
        updateStatusBar("Scan history cleared.");
        generateStatusPage();
    }
}

// ****************************************************************************
// clearUpdatesHistoryButtonClicked()
// ****************************************************************************
void MainWindow::clearUpdatesHistoryButtonClicked()
{
    QMessageBox::StandardButton reply;
    reply = QMessageBox::question(this,
                                  tr("Clear Update History"),
                                  tr("Are you sure you want to clear all update history and "
                                     "associated reports ?\nThis "
                                     "action cannot be undone."),
                                  QMessageBox::Yes | QMessageBox::No);
    if (reply == QMessageBox::Yes) {
        // Clear the table view
        ui->updateHistoryTable->setRowCount(0);

        // Delete the report files
        QString updatesDirPath = QStandardPaths::writableLocation(QStandardPaths::HomeLocation) + "/.calamity/reports/updates";
        QDir dir(updatesDirPath);
        if (dir.exists()) {
            dir.setNameFilters(QStringList() << "*.html");
            dir.setFilter(QDir::Files);
            for(const QString &dirFile : dir.entryList()) {
                dir.remove(dirFile);
            }
        }
        updateStatusBar("Update history cleared.");
        generateStatusPage();
    }
}

// ****************************************************************************
// updateVersionInfo()
// ****************************************************************************
void MainWindow::updateVersionInfo()
{
    if (versionCheckProcess->state() == QProcess::Running) {
        qDebug() << "ClamAV version check process already running.";
        return;
    }
    if (m_onlineVersionCheckProcess->state() == QProcess::Running) {
        qDebug() << "Online version check process already running.";
        return;
    }

    // Display Application Version
    if (ui->appVersionLabel) {
        ui->appVersionLabel->setText(QString("Calamity Version : %1.%2-%3")
                                         .arg(APP_VERSION)
                                         .arg(GIT_COMMIT_COUNT)
                                         .arg(GIT_HASH));
    }

    // Clear previous info
    if (clamavVersionLabel)
        clamavVersionLabel->setText(tr("ClamAV Version : Fetching..."));
    if (signatureVersionLabel)
        signatureVersionLabel->setText(tr("Local Signature Version : Fetching..."));
    if (ui->lblCurrentUpdate)
        ui->lblCurrentUpdate->setText(tr("Online Signature Version available : Fetching..."));

    // Fetch ClamAV version
    versionCheckProcess->start("clamscan", QStringList() << "--version");
    versionCheckProcess->waitForFinished();
    QString clamavOutput = versionCheckProcess->readAllStandardOutput();
    QRegularExpression clamavRx("ClamAV (\\d+\\.\\d+\\.\\d+)");
    QRegularExpressionMatch clamavMatch = clamavRx.match(clamavOutput);
    if (clamavMatch.hasMatch()) {
        m_clamavVersion = clamavMatch.captured(1);
        if (clamavVersionLabel)
            clamavVersionLabel->setText(tr("ClamAV Version : %1").arg(m_clamavVersion));
    } else {
        m_clamavVersion.clear();
        if (clamavVersionLabel)
            clamavVersionLabel->setText(tr("ClamAV Version : Not Found"));
        qWarning() << "Could not parse ClamAV version from:" << clamavOutput;
    }

    // Fetch Signature version from clamscan --version output
    // The format is typically "ClamAV X.Y.Z/SIGNATURE_VERSION/DATE"
    QRegularExpression signatureRx("ClamAV \\d+\\.\\d+\\.\\d+/(\\d+)/(.+)");
    QRegularExpressionMatch signatureMatch = signatureRx.match(clamavOutput);
    if (signatureMatch.hasMatch()) {
        QString signatureVer = signatureMatch.captured(1);
        QString signatureDate = signatureMatch.captured(2).trimmed();
        m_signatureVersionInfo = tr("%1 (Last Updated: %2)").arg(signatureVer, signatureDate);
        if (signatureVersionLabel)
            signatureVersionLabel
                ->setText(tr("Local Signature Version : %1").arg(m_signatureVersionInfo));
    } else {
        m_signatureVersionInfo.clear();
        if (signatureVersionLabel)
            signatureVersionLabel->setText(tr("Local Signature Version : Not Found"));
        qWarning() << "Could not parse Signature version from clamscan output:" << clamavOutput;
    }

    // Fetch online signature version
    m_onlineVersionCheckProcess->start("host", QStringList() << "-t" << "txt" << "current.cvd.clamav.net");
}

// ****************************************************************************
// onOnlineVersionCheckFinished()
// ****************************************************************************
void MainWindow::onOnlineVersionCheckFinished()
{
    QString output = m_onlineVersionCheckProcess->readAllStandardOutput();
    qDebug() << "Online version check output: " << output;

    // Expected format: "current.cvd.clamav.net descriptive text "0.103.9:62:27032:1689253200:1:90:49192:336""
    // We need the third field from the quoted string.
    QRegularExpression rx(R"("[^:]*:[^:]*:(\d+):[^"]*")");
    QRegularExpressionMatch match = rx.match(output);

    if (match.hasMatch()) {
        QString onlineVersionStr = match.captured(1);
        int onlineVersion = onlineVersionStr.toInt();
        qDebug() << "Online version string: " << onlineVersionStr << ", int: " << onlineVersion;

        // Extract local signature version for comparison
        // m_signatureVersionInfo is in format "VERSION (Last Updated: DATE)"
        QRegularExpression localSigRx(R"((?:ClamAV \d+\.\d+\.\d+/)?(\d+) \(Last Updated: .*\))");
        QRegularExpressionMatch localSigMatch = localSigRx.match(m_signatureVersionInfo);
        int localVersion = 0;
        if (localSigMatch.hasMatch()) {
            localVersion = localSigMatch.captured(1).toInt();
        }
        qDebug() << "Local signature info: " << m_signatureVersionInfo << ", extracted local version: " << localVersion;

        if (ui->lblCurrentUpdate) {
            if (onlineVersion > localVersion) {
                ui->lblCurrentUpdate->setText(
                    tr("Online Signatures Version available : %1 (New version available!)")
                        .arg(onlineVersionStr));
                trayIcon->showMessage("Calamity",
                                      tr("New Signatures Version avaialable online."),
                                      QSystemTrayIcon::Warning,
                                      2000);
                if (ui->asapUpdateCheckBox->isChecked()) {
                    updateNowButtonClicked();
                }
            } else if (onlineVersion == localVersion && localVersion != 0) {
                ui->lblCurrentUpdate
                    ->setText(tr("Online Signatures Version available : %1 (Up to date)")
                                  .arg(onlineVersionStr));
            } else {
                ui->lblCurrentUpdate
                    ->setText(tr("Online Signatures Version available : %1").arg(onlineVersionStr));
            }
        }
    } else {
        if (ui->lblCurrentUpdate) {
            ui->lblCurrentUpdate
                ->setText(tr("Online Signature Version available : Could not fetch"));
        }
        qWarning() << "Could not parse online signature version from:" << output;
    }

    generateStatusPage();
}

// ****************************************************************************
// scheduledRecursiveScanCheckBox_toggled()
// ****************************************************************************
void MainWindow::scheduledRecursiveScanCheckBox_toggled(bool checked)
{
    m_scheduledRecursiveScanEnabled = checked;
}

// ****************************************************************************
// scheduledHeuristicAlertsCheckBox_toggled()
// ****************************************************************************
void MainWindow::scheduledHeuristicAlertsCheckBox_toggled(bool checked)
{
    m_scheduledHeuristicAlertsEnabled = checked;
}

// ****************************************************************************
// scheduledEncryptedDocumentsAlertsCheckBox_toggled()
// ****************************************************************************
void MainWindow::scheduledEncryptedDocumentsAlertsCheckBox_toggled(bool checked)
{
    m_scheduledEncryptedDocumentsAlertsEnabled = checked;
}

// ****************************************************************************
// scheduledDetectPuaCheckBox_toggled()
// ****************************************************************************
void MainWindow::scheduledDetectPuaCheckBox_toggled(bool checked)
{
    m_scheduledDetectPuaEnabled = checked;
}

// ****************************************************************************
// scheduledScanArchivesCheckBox_toggled
// ****************************************************************************
void MainWindow::scheduledScanArchivesCheckBox_toggled(bool checked)
{
    m_scheduledScanArchivesEnabled = checked;
}

// ****************************************************************************
// scheduledMoveInfectedCheckBox_toggled()
// ****************************************************************************
void MainWindow::scheduledMoveInfectedCheckBox_toggled(bool checked)
{
    m_scheduledMoveInfectedEnabled = checked;
    ui->scheduledQuarantinePathLineEdit->setEnabled(checked);
    ui->browseScheduledQuarantineButton->setEnabled(checked);
}

// ****************************************************************************
// scheduledRemoveInfectedCheckBox_toggled()
// ****************************************************************************
void MainWindow::scheduledRemoveInfectedCheckBox_toggled(bool checked)
{
    m_scheduledRemoveInfectedEnabled = checked;
}

// ****************************************************************************
// browseScheduledQuarantineButtonClicked()
// ****************************************************************************
void MainWindow::browseScheduledQuarantineButtonClicked()
{
    QString path = QFileDialog::getExistingDirectory(this, tr("Select Scheduled Quarantine Directory"),
                                                 QDir::homePath(),
                                                 QFileDialog::ShowDirsOnly | QFileDialog::DontResolveSymlinks);
    if (!path.isEmpty()) {
        ui->scheduledQuarantinePathLineEdit->setText(path);
    }
}

// ****************************************************************************
// updateScanStatusLed()
// ****************************************************************************
void MainWindow::updateScanStatusLed(bool scanning)
{
    if (scanning) {
        scanStatusLed->setPixmap(ledGreenPixmap);
    } else {
        scanStatusLed->setPixmap(ledGrayPixmap);
    }
}

// ****************************************************************************
// on_scanHistoryTable_cellDoubleClicked()
// ****************************************************************************
void MainWindow::on_scanHistoryTable_cellDoubleClicked(int row, int column)
{
    Q_UNUSED(column); // Column is not used in this slot

    if (row < 0 || row >= scanHistory.size()) {
        qWarning() << "Double clicked row out of bounds:" << row;
        return;
    }

    // Retrieve the timestamp from the clicked row (assuming it's in column 0)
    QTableWidgetItem *timestampItem = ui->scanHistoryTable->item(row, 0);
    if (!timestampItem) {
        qWarning() << "Could not retrieve timestamp item from row:" << row;
        return;
    }

    // The timestamp in the table is formatted as "yyyy-MM-dd hh:mm:ss"
    // The filename is "yyyy-MM-dd_hh-mm-ss.zip"
    QString timestampStr = timestampItem->text();
    QDateTime timestamp = QDateTime::fromString(timestampStr, "yyyy-MM-dd hh:mm:ss");

    if (!timestamp.isValid()) {
        qWarning() << "Invalid timestamp format in table:" << timestampStr;
        QMessageBox::warning(this, tr("Error"), tr("Could not parse timestamp from selected row."));
        return;
    }

    QString reportFileName = timestamp.toString("yyyy-MM-dd_hh-mm-ss") + ".zip";
    QString scansDirPath = QStandardPaths::writableLocation(QStandardPaths::HomeLocation) + "/.calamity/reports/scans";
    QString reportFilePath = scansDirPath + "/" + reportFileName;

    QFile file(reportFilePath);
    if (file.exists()) {
        qDebug() << "Opening report file:" << reportFilePath;
        QDesktopServices::openUrl(QUrl::fromLocalFile(reportFilePath));
    } else {
        qWarning() << "Report file not found:" << reportFilePath;
        QMessageBox::warning(this, tr("File Not Found"),
                             tr("The corresponding scan report could not be found at:\n%1").arg(reportFilePath));
    }
}

// ****************************************************************************
// handleFileDropped()
// ****************************************************************************
void MainWindow::handleFileDropped(const QString &path)
{
    qDebug() << "File dropped signal received in MainWindow:" << path;
    appendPathToLineEdit(ui->pathLineEdit, path);
    ui->outputLog->clear();
    ui->outputLog->append(QString("Scanning: %1").arg(joinPathsForDisplay(parsePathsText(ui->pathLineEdit->text()))));
    QApplication::processEvents(); // Force UI update
    scanButton_clicked();
}

// ****************************************************************************
// onEmailReportCheckBox_toggled()
// ****************************************************************************
void MainWindow::onEmailReportCheckBox_toggled(bool checked)
{
    // Enable/disable email settings fields based on checkbox state
    ui->smtpServerLineEdit->setEnabled(checked);
    ui->smtpPortLineEdit->setEnabled(checked);
    ui->smtpUsernameLineEdit->setEnabled(checked);
    ui->smtpPasswordLineEdit->setEnabled(checked);
    ui->recipientLineEdit->setEnabled(checked);
    ui->saveEmailSettingsButton->setEnabled(checked);
    ui->testEmailButton->setEnabled(checked);
}

// ****************************************************************************
// onSaveEmailSettingsButton_clicked()
// ****************************************************************************
void MainWindow::onSaveEmailSettingsButton_clicked()
{
    saveEmailSettings();
}

// ****************************************************************************
// onTestEmailButton_clicked()
// ****************************************************************************
void MainWindow::onTestEmailButton_clicked()
{
    QString smtpServer = ui->smtpServerLineEdit->text();
    int smtpPort = ui->smtpPortLineEdit->text().toInt();
    QString smtpUsername = ui->smtpUsernameLineEdit->text();
    QString smtpPassword = ui->smtpPasswordLineEdit->text();
    QString recipient = ui->recipientLineEdit->text();

    if (smtpServer.isEmpty() || smtpPort == 0 || recipient.isEmpty()) {
        QMessageBox::warning(this, tr("Email Settings Error"), tr("Please fill in SMTP Server, Port, and Recipient fields."));
        return;
    }

    ui->testEmailButton->setEnabled(false);
    updateStatusBar("Sending test email...");

    // Clean up previous client if exists
    if (smtpClient) {
        smtpClient->deleteLater();
    }

    smtpClient = new SmtpClient(smtpServer, smtpPort, SmtpClient::TlsConnection);

    connect(smtpClient, &SmtpClient::connected, this, &MainWindow::handleSmtpConnected);
    connect(smtpClient, &SmtpClient::authenticated, this, &MainWindow::handleSmtpAuthenticated);
    connect(smtpClient, &SmtpClient::mailSent, this, &MainWindow::handleSmtpMailSent);
    connect(smtpClient, QOverload<SmtpClient::SmtpError>::of(&SmtpClient::error), this, &MainWindow::handleSmtpError);
    connect(smtpClient, &SmtpClient::disconnected, this, &MainWindow::handleSmtpDisconnected);

    smtpClient->connectToHost();
}

// ****************************************************************************
// handleSmtpConnected()
// ****************************************************************************
void MainWindow::handleSmtpConnected()
{
    qDebug() << "SMTP Connected.";
    updateStatusBar("SMTP Connected. Attempting to log in...");
    QString smtpUsername = ui->smtpUsernameLineEdit->text();
    QString smtpPassword = ui->smtpPasswordLineEdit->text();

    if (!smtpUsername.isEmpty() && !smtpPassword.isEmpty()) {
        smtpClient->login(smtpUsername, smtpPassword);
    } else {
        // If no username/password, try sending without authentication (might fail for most servers)
        qDebug() << "No SMTP username/password provided. Attempting to send without authentication.";
        MimeMessage message;
        EmailAddress sender(ui->smtpUsernameLineEdit->text().isEmpty() ? "test@example.com" : ui->smtpUsernameLineEdit->text(), "Calamity Test");
        message.setSender(sender);
        EmailAddress recipient(ui->recipientLineEdit->text(), "Recipient");
        message.addRecipient(recipient);
        message.setSubject("Calamity Test Email");
        MimeText text;
        text.setText("This is a test email sent from Calamity.");
        message.addPart(&text);
        smtpClient->sendMail(message);
    }
}

// ****************************************************************************
// handleSmtpAuthenticated()
// ****************************************************************************
void MainWindow::handleSmtpAuthenticated()
{
    qDebug() << "SMTP Authenticated.";
    updateStatusBar("SMTP Authenticated. Sending test email...");
    MimeMessage message;
    EmailAddress sender(ui->smtpUsernameLineEdit->text(), "Calamity Test");
    message.setSender(sender);
    EmailAddress recipient(ui->recipientLineEdit->text(), "Recipient");
    message.addRecipient(recipient);
    message.setSubject("Calamity Test Email");
    MimeText text;
    text.setText("This is a test email sent from Calamity.");
    message.addPart(&text);
    smtpClient->sendMail(message);
}

// ****************************************************************************
// handleSmtpMailSent()
// ****************************************************************************
void MainWindow::handleSmtpMailSent()
{
    qDebug() << "SMTP Mail Sent.";
    QMessageBox::information(this, tr("Test Email Sent"), tr("Test email sent successfully!"));
    updateStatusBar("Test email sent.");
    smtpClient->quit();
}

// ****************************************************************************
// handleSmtpError()
// ****************************************************************************
void MainWindow::handleSmtpError(SmtpClient::SmtpError e)
{
    QString errorString = SmtpClient::string(e);
    qWarning() << "SMTP Error:" << errorString;
    QMessageBox::critical(this, tr("Email Error"), tr("Failed to send test email: %1").arg(errorString));
    updateStatusBar(QString("Email error: %1").arg(errorString));
    smtpClient->quit();
}

// ****************************************************************************
// handleSmtpDisconnected()
// ****************************************************************************
void MainWindow::handleSmtpDisconnected()
{
    qDebug() << "SMTP Disconnected.";
    ui->testEmailButton->setEnabled(true);
    if (smtpClient) {
        smtpClient->deleteLater();
        smtpClient = nullptr;
    }
    updateStatusBar("Ready");
}

// ****************************************************************************
// sendEmailReport()
// ****************************************************************************
void MainWindow::sendEmailReport(const QString &reportPath)
{
    QString smtpServer = ui->smtpServerLineEdit->text();
    int smtpPort = ui->smtpPortLineEdit->text().toInt();
    QString smtpUsername = ui->smtpUsernameLineEdit->text();
    QString smtpPassword = ui->smtpPasswordLineEdit->text();
    QString recipient = ui->recipientLineEdit->text();

    if (smtpServer.isEmpty() || smtpPort == 0 || recipient.isEmpty()) {
        qWarning() << "Email settings incomplete. Cannot send report.";
        return;
    }

    if (!QFile::exists(reportPath)) {
        qWarning() << "Report file does not exist. Cannot send report:" << reportPath;
        return;
    }

    // Clean up previous client if exists
    if (smtpClient) {
        smtpClient->deleteLater();
    }

    smtpClient = new SmtpClient(smtpServer, smtpPort, SmtpClient::TlsConnection);

    connect(smtpClient, &SmtpClient::connected, this, &MainWindow::handleSmtpConnected);
    connect(smtpClient, &SmtpClient::authenticated, this, &MainWindow::handleSmtpAuthenticated);
    connect(smtpClient, &SmtpClient::mailSent, this, &MainWindow::handleSmtpMailSent);
    connect(smtpClient, QOverload<SmtpClient::SmtpError>::of(&SmtpClient::error), this, &MainWindow::handleSmtpError);
    connect(smtpClient, &SmtpClient::disconnected, this, &MainWindow::handleSmtpDisconnected);

    MimeMessage message;
    EmailAddress sender(smtpUsername, "Calamity Report");
    message.setSender(sender);
    EmailAddress to(recipient, "Report Recipient");
    message.addRecipient(to);

    message.setSubject("Calamity Scan Report - " + QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm"));

    MimeText *text = new MimeText();
    text->setText("Please find the attached Calamity scan report.");
    message.addPart(text);

    MimeAttachment *attachment = new MimeAttachment(new QFile(reportPath));
    message.addPart(attachment);

    smtpClient->connectToHost();
    smtpClient->sendMail(message);

    // message and its parts will be deleted by smtpClient
}

// ****************************************************************************
// checkForUpdates()
// ****************************************************************************
void MainWindow::checkForUpdates()
{
    m_updateCheckProcess->start("git", QStringList() << "ls-remote" << "https://github.com/jplozf/calamity.git" << "HEAD");
}

// ****************************************************************************
// onVersionCheckFinished()
// ****************************************************************************
void MainWindow::onVersionCheckFinished()
{
    QString output = m_updateCheckProcess->readAllStandardOutput();
    if (output.isEmpty()) {
        return; // Or handle error
    }

    QString remoteHash = output.left(7);
    QString localHash = GIT_HASH;

    if (remoteHash != localHash) {
        QMessageBox::information(this, tr("New Version Available"), tr("A new version of Calamity is available on GitHub."));
        trayIcon->showMessage("Calamity",
                              tr("A new version of Calamity is available on GitHub."),
                              QSystemTrayIcon::Warning,
                              2000);
    }
}

// ****************************************************************************
// onVersionCheckTimerTimeout()
// ****************************************************************************
void MainWindow::onVersionCheckTimerTimeout()
{
    checkForUpdates();
}

// ****************************************************************************
// onVersionCheckIntervalLineEditChanged()
// ****************************************************************************
void MainWindow::onVersionCheckIntervalLineEditChanged()
{
    bool ok;
    int newInterval = m_versionCheckIntervalLineEdit->text().toInt(&ok);
    if (ok && newInterval > 0) {
        m_versionCheckInterval = newInterval;
        // Restart the timer with the new interval
        m_versionCheckTimer->stop();
        m_versionCheckTimer->start(m_versionCheckInterval * 60 * 1000);
        updateStatusBar(tr("Version check interval set to %1 minutes.").arg(newInterval));
    } else {
        QMessageBox::warning(this, tr("Invalid Input"), tr("Please enter a valid positive number for the version check interval."));
        // Revert to the last valid value if input is invalid
        m_versionCheckIntervalLineEdit->setText(QString::number(m_versionCheckInterval));
    }
}

// ****************************************************************************
// generateUpdateReport()
// ****************************************************************************
void MainWindow::generateUpdateReport(const QByteArray &logData)
{
    QString reportPath = QDir::tempPath() + "/update_report.html";
    QFile reportFile(reportPath);
    if (reportFile.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QString hostname = QHostInfo::localHostName();
        QString kernel = QSysInfo::prettyProductName() + " (" + QSysInfo::kernelType() + " " + QSysInfo::kernelVersion() + ")";
        qint64 elapsedMs = m_updateTimer.isValid() ? m_updateTimer.elapsed() : 0;

        // Optional embedded logo as data URI
        QString logoTag;
        {
            QFile logo(":/icons/app_icon_64x64.png");
            if (logo.open(QIODevice::ReadOnly)) {
                const QByteArray logoData = logo.readAll();
                const QString base64 = QString::fromLatin1(logoData.toBase64());
                logoTag = QString("<img src=\"data:image/png;base64,%1\" alt=\"Calamity\" style=\"width:64px;height:64px;vertical-align:middle;margin-right:10px;\"/>").arg(base64);
            }
        }

        // Build simple HTML
        QString html;
        html += "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>Calamity Update Report</title>";
        html += "<style>body{font-family:sans-serif;background:#FADA5E;color:#111}h1{margin-bottom:0}small{color:#555}table{border-collapse:collapse;margin:10px 0}td,th{border:1px solid #ccc;padding:6px 8px;text-align:left}code,pre{background:#f7f7f9;border:1px solid #e1e1e8;padding:8px;display:block;white-space:pre-wrap;}</style></head><body>";

        if (!logoTag.isEmpty()) {
            html += "<div style=\"display:flex;align-items:center;gap:10px;\">" + logoTag + "<div>";
            html += "<h1>Calamity Update Report</h1>";
            html += QString("<small>Generated: %1</small>").arg(QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss"));
            html += "</div></div>";
        } else {
            html += "<h1>Calamity Update Report</h1>";
            html += QString("<small>Generated: %1</small>").arg(QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss"));
        }

        html += "<h2>Summary</h2><table>";
        html += QString("<tr><th>Command</th><td><code>%1 %2</code></td></tr>").arg(m_lastCommand.toHtmlEscaped()).arg(m_lastArguments.join(' ').toHtmlEscaped());
        html += QString("<tr><th>Application</th><td>Calamity %1.%2-%3</td></tr>").arg(APP_VERSION).arg(GIT_COMMIT_COUNT).arg(GIT_HASH);
        if (!m_clamavVersion.isEmpty()) {
            html += QString("<tr><th>ClamAV Engine</th><td>%1</td></tr>").arg(m_clamavVersion.toHtmlEscaped());
        }
        if (!m_signatureVersionInfo.isEmpty()) {
            html += QString("<tr><th>Signatures</th><td>%1</td></tr>").arg(m_signatureVersionInfo.toHtmlEscaped());
        }
        html += QString("<tr><th>Hostname</th><td>%1</td></tr>").arg(hostname.toHtmlEscaped());
        html += QString("<tr><th>OS/Kernel</th><td>%1</td></tr>").arg(kernel.toHtmlEscaped());
        html += QString("<tr><th>Started</th><td>%1</td></tr>").arg(m_updateStartedAt.toString("yyyy-MM-dd hh:mm:ss"));
        html += QString("<tr><th>Ended</th><td>%1</td></tr>")
                    .arg(QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss"));
        html += QString("<tr><th>Elapsed</th><td>%1</td></tr>").arg(timeConversion(elapsedMs));
        html += "</table>";

        html += "<h2>Raw Output</h2><pre>" + QString::fromUtf8(logData).toHtmlEscaped() + "</pre>";
        html += "</body></html>";

        QTextStream out(&reportFile);
        out.setCodec("UTF-8");
        out << html;
        reportFile.close();

        QString updatesDirPath = QStandardPaths::writableLocation(QStandardPaths::HomeLocation) + "/.calamity/reports/updates";
        QDir updatesDir(updatesDirPath);
        if (!updatesDir.exists()) {
            updatesDir.mkpath(".");
        }

        QString timestamp = QDateTime::currentDateTime().toString("yyyy-MM-dd_hh-mm-ss");
        QString reportFileName = QString("%1.html").arg(timestamp);
        QString reportFilePath = updatesDirPath + "/" + reportFileName;

        if (reportFile.copy(reportFilePath)) {
            qDebug() << "Update log saved to:" << reportFilePath;
            m_lastReportPath = reportFilePath;
        } else {
            qWarning() << "Could not save update log to:" << reportFilePath;
        }

        reportFile.remove();
    } else {
        qWarning() << "Could not create temporary report file:" << reportPath;
    }
}

// ****************************************************************************
// generateStatusPage()
// ****************************************************************************
void MainWindow::generateStatusPage()
{
    QString reportsDirPath = QStandardPaths::writableLocation(QStandardPaths::HomeLocation) + "/.calamity/reports";
    QDir reportsDir(reportsDirPath);
    if (!reportsDir.exists()) {
        reportsDir.mkpath(".");
    }

    QString statusFilePath = reportsDirPath + "/status.html";
    QFile statusFile(statusFilePath);

    if (!statusFile.open(QIODevice::WriteOnly | QIODevice::Text)) {
        qWarning() << "Could not create status page file:" << statusFilePath;
        return;
    }

    // Optional embedded logo as data URI
    QString logoTag;
    {
        QFile logo(":/icons/app_icon_64x64.png");
        if (logo.open(QIODevice::ReadOnly)) {
            const QByteArray logoData = logo.readAll();
            const QString base64 = QString::fromLatin1(logoData.toBase64());
            logoTag = QString("<img src=\"data:image/png;base64,%1\" alt=\"Calamity\" style=\"width:64px;height:64px;vertical-align:middle;margin-right:10px;\"/>").arg(base64);
        }
    }

    QString html;
    html += "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>Calamity Status Report</title>";
    html += "<style>body{font-family:sans-serif;background:#FADA5E;color:#111}h1,h2{margin-bottom:0}small{color:#555}table{border-collapse:collapse;margin:10px 0}td,th{border:1px solid #ccc;padding:6px 8px;text-align:left}ul{list-style-type:none;padding:0}li{margin-bottom:5px}a{color:#007bff;text-decoration:none}a:hover{text-decoration:underline}</style></head><body>";

    if (!logoTag.isEmpty()) {
        html += "<div style=\"display:flex;align-items:center;gap:10px;\">" + logoTag + "<div>";
        html += "<h1>Calamity Protection Status</h1>";
        html += QString("<small>Generated: %1</small>").arg(QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss"));
        html += QString("<p>Application Version: Calamity %1.%2-%3</p>").arg(APP_VERSION).arg(GIT_COMMIT_COUNT).arg(GIT_HASH);
        html += "</div></div>";
    } else {
        html += "<h1>Calamity Protection Status</h1>";
        html += QString("<small>Generated: %1</small>").arg(QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss"));
        html += QString("<p>Application Version: Calamity %1.%2-%3</p>").arg(APP_VERSION).arg(GIT_COMMIT_COUNT).arg(GIT_HASH);
    }

    html += "<h2>ClamAV Status</h2><table>";
    html += QString("<tr><th>ClamAV Engine Version</th><td>%1</td></tr>").arg(m_clamavVersion.isEmpty() ? "N/A" : m_clamavVersion.toHtmlEscaped());
    html += QString("<tr><th>Local Signature Version</th><td>%1</td></tr>").arg(m_signatureVersionInfo.isEmpty() ? "N/A" : m_signatureVersionInfo.toHtmlEscaped());
    html += QString("<tr><th>Online Signature Version</th><td>%1</td></tr>").arg(ui->lblCurrentUpdate->text().replace("Online Signature Version available : ", "").toHtmlEscaped());
    html += "</table>";

    html += "<div style=\"display:flex; gap: 20px;\">"; // Flex container for two columns

    // Scan Reports Column
    html += "<div style=\"flex: 1;\">"; // Each column takes equal width
    html += "<h2>Scan Reports</h2><ul>";
    QString scansDirPath = reportsDirPath + "/scans";
    QDir scansDir(scansDirPath);
    if (scansDir.exists()) {
        QStringList filters;
        filters << "*.html";
        QFileInfoList scanReports = scansDir.entryInfoList(filters, QDir::Files | QDir::NoSymLinks);
        std::sort(scanReports.begin(), scanReports.end(), [](const QFileInfo &a, const QFileInfo &b) {
            return a.lastModified() > b.lastModified(); // Newest first
        });
        if (scanReports.isEmpty()) {
            html += "<li>No scan reports available.</li>";
        } else {
            for (const QFileInfo &fileInfo : scanReports) {
                html += QString("<li><a href=\"scans/%1\">%2</a></li>").arg(fileInfo.fileName(), fileInfo.baseName());
            }
        }
    } else {
        html += "<li>Scan reports directory not found.</li>";
    }
    html += "</ul>";
    html += "</div>"; // Close Scan Reports Column

    // Update Reports Column
    html += "<div style=\"flex: 1;\">"; // Each column takes equal width
    html += "<h2>Update Reports</h2><ul>";
    QString updatesDirPath = reportsDirPath + "/updates";
    QDir updatesDir(updatesDirPath);
    if (updatesDir.exists()) {
        QStringList filters;
        filters << "*.html";
        QFileInfoList updateReports = updatesDir.entryInfoList(filters, QDir::Files | QDir::NoSymLinks);
        std::sort(updateReports.begin(), updateReports.end(), [](const QFileInfo &a, const QFileInfo &b) {
            return a.lastModified() > b.lastModified(); // Newest first
        });
        if (updateReports.isEmpty()) {
            html += "<li>No update reports available.</li>";
        } else {
            for (const QFileInfo &fileInfo : updateReports) {
                html += QString("<li><a href=\"updates/%1\">%2</a></li>").arg(fileInfo.fileName(), fileInfo.baseName());
            }
        }
    } else {
        html += "<li>Update reports directory not found.</li>";
    }
    html += "</ul>";
    html += "</div>"; // Close Update Reports Column

    html += "</div>"; // Close Flex container

    html += "</body></html>";

    QTextStream out(&statusFile);
    out.setCodec("UTF-8");
    out << html;
    statusFile.close();
    qDebug() << "Status page generated at:" << statusFilePath;
}


// ****************************************************************************
// on_asapUpdateCheckBox_stateChanged()
// ****************************************************************************
void MainWindow::on_asapUpdateCheckBox_stateChanged(int state)
{
    bool checked = (state == Qt::Checked);
    ui->enableUpdateScheduleCheckBox->setDisabled(checked);
    ui->updateFrequencyComboBox->setDisabled(checked);
    ui->updateTimeEdit->setDisabled(checked);

    if (checked) {
        updateSchedulerTimer->stop();
        // When ASAP is checked, we can trigger an immediate online version check.
        // The existing timer-based check logic can be reused or adapted.
        // For now, let's just call the online version check.
        updateVersionInfo();
        ui->lblNextUpdateScheduled->setText(tr("ASAP +/- %1 minutes").arg(ui->versionCheckIntervalLineEdit->text()));
    } else {
        // Revert to the scheduled update time if unchecked
        startUpdateScheduler();
    }
}

// ****************************************************************************
// timeConversion()
// ****************************************************************************
// ****************************************************************************
// timeConversion()
// ****************************************************************************
QString MainWindow::timeConversion(qint64 milliseconds)
{
    if (milliseconds < 0) return "N/A";

    qint64 seconds = milliseconds / 1000;
    qint64 minutes = seconds / 60;
    qint64 hours = minutes / 60;
    seconds %= 60;
    minutes %= 60;

    if (hours > 0)
        return QString("%1h %2m %3s").arg(hours).arg(minutes).arg(seconds);
    else if (minutes > 0)
        return QString("%1m %2s").arg(minutes).arg(seconds);
    else
        return QString("%1s").arg(seconds);
}
