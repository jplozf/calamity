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

// ****************************************************************************
// MainWindow()
// ****************************************************************************
MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
    , clamscanProcess(nullptr)
    , scanStatusLed(nullptr)
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

    // Connect QProcess signals to slots
    connect(clamscanProcess, &QProcess::readyReadStandardOutput, this, &MainWindow::readClamscanOutput);
    connect(clamscanProcess, &QProcess::readyReadStandardError, this, &MainWindow::readClamscanOutput);
    connect(clamscanProcess, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished), this, &MainWindow::clamscanFinished);
    connect(clamscanProcess, &QProcess::errorOccurred, this, &MainWindow::clamscanErrorOccurred);

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
    connect(ui->browseQuarantineButton, &QPushButton::clicked, this, &MainWindow::browseQuarantineButtonClicked);
    connect(ui->browseScheduledScanPathButton, &QPushButton::clicked, this, &MainWindow::browseScheduledScanPathButtonClicked);
    connect(ui->recursiveScanCheckBox, &QCheckBox::toggled, this, &MainWindow::recursiveScanCheckBox_toggled);
    connect(ui->heuristicAlertsCheckBox, &QCheckBox::toggled, this, &MainWindow::heuristicAlertsCheckBox_toggled);
    connect(ui->encryptedDocumentsAlertsCheckBox, &QCheckBox::toggled, this, &MainWindow::encryptedDocumentsAlertsCheckBox_toggled);
    connect(ui->scheduledRecursiveScanCheckBox, &QCheckBox::toggled, this, &MainWindow::scheduledRecursiveScanCheckBox_toggled);
    connect(ui->scheduledHeuristicAlertsCheckBox, &QCheckBox::toggled, this, &MainWindow::scheduledHeuristicAlertsCheckBox_toggled);
    connect(ui->scheduledEncryptedDocumentsAlertsCheckBox, &QCheckBox::toggled, this, &MainWindow::scheduledEncryptedDocumentsAlertsCheckBox_toggled);
    connect(ui->scheduledScanArchivesCheckBox, &QCheckBox::toggled, this, &MainWindow::scheduledScanArchivesCheckBox_toggled);
    connect(ui->scheduledBellOnVirusCheckBox, &QCheckBox::toggled, this, &MainWindow::scheduledBellOnVirusCheckBox_toggled);
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

    // Connect fileDropped signal from custom QTextEdit
    connect(ui->outputLog, &ScanOutputTextEdit::fileDropped, this, &MainWindow::handleFileDropped);

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
    scanAction->setIcon(QIcon(":/icons/Search.png"));
    connect(scanAction, &QAction::triggered, this, &MainWindow::scanActionTriggered);
    trayMenu->addAction(scanAction);

    QAction *showHideAction = new QAction(tr("Show / Hide"), this);
    showHideAction->setIcon(QIcon(":/icons/Application.png"));
    connect(showHideAction, &QAction::triggered, this, &MainWindow::showHideActionTriggered);
    trayMenu->addAction(showHideAction);

    trayMenu->addSeparator();

    QAction *quitAction = new QAction(tr("Quit"), this);
    quitAction->setIcon(QIcon(":/icons/Cancel.png"));
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
        ui->pathLineEdit->setText(path);
    }
}

// ****************************************************************************
// scanButton_clicked()
// ****************************************************************************
void MainWindow::scanButton_clicked()
{
    qDebug() << "scanButton_clicked() called.";
    QString pathToScan = ui->pathLineEdit->text();
    qDebug() << "Path to scan from pathLineEdit:" << pathToScan;
    if (pathToScan.isEmpty()) {
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
    ui->outputLog
        ->append(QString("Scan of '%1' started at %2").arg(pathToScan, QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss")));
    updateStatusBar("Scan in progress...");
    updateScanStatusLed(true); // Explicitly set LED to green when scan starts
    ui->scanButton->setEnabled(false);
    ui->stopButton->setEnabled(true);

    QStringList arguments = buildClamscanArguments();
    arguments << pathToScan; // Add the path to scan as the last argument

    qDebug() << "Executing clamscan with arguments:" << arguments;

    QString command = "clamscan";
    if (ui->sudoCheckBox->isChecked()) {
        command = "sudo";
        arguments.prepend("clamscan");
    }

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

    if (m_logFile) {
        m_logFile->seek(0);
        QByteArray logData = m_logFile->readAll();
        m_logFile->close();
        delete m_logFile;
        m_logFile = nullptr;

        if (!logData.isEmpty()) {
            QString reportPath = QDir::tempPath() + "/report.txt";
            QFile reportFile(reportPath);
            if (reportFile.open(QIODevice::WriteOnly)) {
                reportFile.write(logData);
                reportFile.close();

                QString scansDirPath = QStandardPaths::writableLocation(QStandardPaths::HomeLocation) + "/.calamity/scans";
                QDir scansDir(scansDirPath);
                if (!scansDir.exists()) {
                    scansDir.mkpath(".");
                }

                QString timestamp = QDateTime::currentDateTime().toString("yyyy-MM-dd_hh-mm-ss");
                QString zipFileName = QString("%1.zip").arg(timestamp);
                QString zipFilePath = scansDirPath + "/" + zipFileName;

                QProcess zipProcess;
                zipProcess.start("zip", QStringList() << "-j" << zipFilePath << reportPath);
                zipProcess.waitForFinished(-1);

                if (zipProcess.exitCode() == 0) {
                    qDebug() << "Scan log saved to:" << zipFilePath;
                } else {
                    qWarning() << "Could not save compressed scan log to:" << zipFilePath;
                    qWarning() << "zip process error:" << zipProcess.readAllStandardError();
                }

                reportFile.remove();
            } else {
                qWarning() << "Could not create temporary report file:" << reportPath;
            }
        }
    }

    QString statusMessage;
    QString scanStatus;
    int threats = 0;

    if (exitCode == 0) {
        statusMessage = "Scan finished: No threats found.";
        scanStatus = "Clean";
        trayIcon->showMessage("Calamity",
                              tr("Scan finished.\nNo threats found."),
                              QSystemTrayIcon::Information,
                              2000);
    } else if (exitCode == 1) {
        statusMessage = "Scan finished: Threats found!";
        scanStatus = "Threats Found";
        // Attempt to parse threats found from outputLog
        QString output = ui->outputLog->toPlainText();
        QRegularExpression threatsRx("Infected files: (\\d+)");
        QRegularExpressionMatch threatsMatch = threatsRx.match(output);
        if (threatsMatch.hasMatch()) {
            threats = threatsMatch.captured(1).toInt();
        }
        trayIcon->showMessage("Calamity",
                              tr("Scan finished.\nThreats found."),
                              QSystemTrayIcon::Critical,
                              2000);
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
    QString scannedPath = ui->pathLineEdit->text();
    qDebug() << "Path from pathLineEdit in clamscanFinished:" << scannedPath;
    addScanResult(scannedPath, scanStatus, threats);

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
    ui->statusbar->showMessage(message);
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
    if (ui->bellOnVirusCheckBox->isChecked()) {
        arguments << "--bell";
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
        ui->scheduledScanPathLineEdit->setText(path);
    }
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
    ui->scheduledScanPathLineEdit->setText(settings->value("ScanSchedule/Path", QDir::homePath()).toString());
    ui->scheduledScanSudoCheckBox->setChecked(settings->value("ScanSchedule/Sudo", false).toBool());
    ui->scheduledRecursiveScanCheckBox->setChecked(settings->value("ScanSchedule/RecursiveScan", false).toBool());
    ui->scheduledHeuristicAlertsCheckBox->setChecked(settings->value("ScanSchedule/HeuristicAlerts", false).toBool());
    ui->scheduledEncryptedDocumentsAlertsCheckBox->setChecked(settings->value("ScanSchedule/EncryptedDocumentsAlerts", false).toBool());
    ui->scheduledScanArchivesCheckBox->setChecked(settings->value("ScanSchedule/ScanArchives", false).toBool());
    ui->scheduledBellOnVirusCheckBox->setChecked(settings->value("ScanSchedule/BellOnVirus", false).toBool());
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
    settings->setValue("ScanSchedule/Path", ui->scheduledScanPathLineEdit->text());
    settings->setValue("ScanSchedule/Sudo", ui->scheduledScanSudoCheckBox->isChecked());
    settings->setValue("ScanSchedule/RecursiveScan", ui->scheduledRecursiveScanCheckBox->isChecked());
    settings->setValue("ScanSchedule/HeuristicAlerts", ui->scheduledHeuristicAlertsCheckBox->isChecked());
    settings->setValue("ScanSchedule/EncryptedDocumentsAlerts", ui->scheduledEncryptedDocumentsAlertsCheckBox->isChecked());
    settings->setValue("ScanSchedule/ScanArchives", ui->scheduledScanArchivesCheckBox->isChecked());
    settings->setValue("ScanSchedule/BellOnVirus", ui->scheduledBellOnVirusCheckBox->isChecked());
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
    }
}

// ****************************************************************************
// startUpdateScheduler()
// ****************************************************************************
void MainWindow::startUpdateScheduler()
{
    updateSchedulerTimer->stop();
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
    }
}

// ****************************************************************************
// runScheduledScan()
// ****************************************************************************
void MainWindow::runScheduledScan()
{
    QString pathToScan = ui->scheduledScanPathLineEdit->text();
    if (pathToScan.isEmpty()) {
        qWarning() << "Scheduled scan path is empty. Skipping scan.";
        updateStatusBar("Scheduled scan skipped: No path specified.");
        return;
    }

    if (clamscanProcess->state() == QProcess::Running) {
        qWarning() << "A scan is already running. Skipping scheduled scan.";
        updateStatusBar("Scheduled scan skipped: Another scan in progress.");
        return;
    }

    ui->outputLog->clear();
    ui->outputLog->append("Scheduled scan started at "
                          + QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss"));
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
    if (ui->scheduledScanArchivesCheckBox->isChecked()) {
        arguments << "--scan-archive";
    }
    if (ui->scheduledBellOnVirusCheckBox->isChecked()) {
        arguments << "--bell";
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
    arguments << pathToScan;

    qDebug() << "Executing scheduled clamscan with arguments:" << arguments;
    QString command = "clamscan";
    if (ui->scheduledScanSudoCheckBox->isChecked()) {
        command = "sudo";
        arguments.prepend("clamscan");
    }
    clamscanProcess->start(command, arguments);

    // After the first run, set the timer for the next day/week/month
    // For simplicity, this example assumes daily. More complex logic needed for weekly/monthly.
    scanSchedulerTimer->setInterval(24 * 60 * 60 * 1000); // Reschedule for next day
    scanSchedulerTimer->setSingleShot(false); // Make it repeating
    scanSchedulerTimer->start();
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
    clamscanProcess->start(command, arguments);

    // After the first run, set the timer for the next day/week
    // For simplicity, this example assumes daily. More complex logic needed for weekly.
    updateSchedulerTimer->setInterval(24 * 60 * 60 * 1000); // Reschedule for next day
    updateSchedulerTimer->setSingleShot(false); // Make it repeating
    updateSchedulerTimer->start();
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
    settings->setValue("path", ui->pathLineEdit->text());
    settings->setValue("scanArchives", ui->scanArchivesCheckBox->isChecked());
    settings->setValue("moveInfected", ui->moveInfectedCheckBox->isChecked());
    settings->setValue("quarantinePath", ui->quarantinePathLineEdit->text());
    settings->setValue("removeInfected", ui->removeInfectedCheckBox->isChecked());
    settings->setValue("bellOnVirus", ui->bellOnVirusCheckBox->isChecked());
    settings->setValue("sudo", ui->sudoCheckBox->isChecked());
    settings->setValue("recursiveScan", ui->recursiveScanCheckBox->isChecked());
    settings->setValue("heuristicAlerts", ui->heuristicAlertsCheckBox->isChecked());
    settings->setValue("encryptedDocumentsAlerts", ui->encryptedDocumentsAlertsCheckBox->isChecked());
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
    ui->pathLineEdit->setText(settings->value("path", QDir::homePath()).toString());
    ui->scanArchivesCheckBox->setChecked(settings->value("scanArchives", false).toBool());
    ui->moveInfectedCheckBox->setChecked(settings->value("moveInfected", false).toBool());
    ui->quarantinePathLineEdit->setText(settings->value("quarantinePath", "").toString());
    ui->removeInfectedCheckBox->setChecked(settings->value("removeInfected", false).toBool());
    ui->bellOnVirusCheckBox->setChecked(settings->value("bellOnVirus", false).toBool());
    ui->sudoCheckBox->setChecked(settings->value("sudo", false).toBool());
    ui->recursiveScanCheckBox->setChecked(settings->value("recursiveScan", false).toBool());
    ui->heuristicAlertsCheckBox->setChecked(settings->value("heuristicAlerts", false).toBool());
    ui->encryptedDocumentsAlertsCheckBox->setChecked(settings->value("encryptedDocumentsAlerts", false).toBool());
    settings->endGroup();

    settings->sync();
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
    reply = QMessageBox::question(this, tr("Clear Scan History"),
                                  tr("Are you sure you want to clear all scan history?"),
                                  QMessageBox::Yes|QMessageBox::No);
    if (reply == QMessageBox::Yes) {
        scanHistory.clear();
        ui->scanHistoryTable->setRowCount(0);
        saveScanHistory(); // Save empty history
        updateStatusBar("Scan history cleared.");
    }
}

// ****************************************************************************
// updateVersionInfo()
// ****************************************************************************
void MainWindow::updateVersionInfo()
{
    if (versionCheckProcess->state() == QProcess::Running) {
        qDebug() << "Version check process already running.";
        return;
    }

    // Display Application Version
    if (ui->appVersionLabel) {
        ui->appVersionLabel->setText(QString("Calamity Version: %1.%2-%3").arg(APP_VERSION).arg(GIT_COMMIT_COUNT).arg(GIT_HASH));
    }

    // Clear previous info
    if (clamavVersionLabel) clamavVersionLabel->setText(tr("ClamAV Version: Fetching..."));
    if (signatureVersionLabel) signatureVersionLabel->setText(tr("Signature Version: Fetching..."));

    // Fetch ClamAV version
    versionCheckProcess->start("clamscan", QStringList() << "--version");
    versionCheckProcess->waitForFinished();
    QString clamavOutput = versionCheckProcess->readAllStandardOutput();
    QRegularExpression clamavRx("ClamAV (\\d+\\.\\d+\\.\\d+)");
    QRegularExpressionMatch clamavMatch = clamavRx.match(clamavOutput);
    if (clamavMatch.hasMatch()) {
        if (clamavVersionLabel) clamavVersionLabel->setText(tr("ClamAV Version: %1").arg(clamavMatch.captured(1)));
    } else {
        if (clamavVersionLabel) clamavVersionLabel->setText(tr("ClamAV Version: Not Found"));
        qWarning() << "Could not parse ClamAV version from:" << clamavOutput;
    }

    // Fetch Signature version from clamscan --version output
    // The format is typically "ClamAV X.Y.Z/SIGNATURE_VERSION/DATE"
    QRegularExpression signatureRx("ClamAV \\d+\\.\\d+\\.\\d+/(\\d+)/(.+)");
    QRegularExpressionMatch signatureMatch = signatureRx.match(clamavOutput);
    if (signatureMatch.hasMatch()) {
        QString signatureVer = signatureMatch.captured(1);
        QString signatureDate = signatureMatch.captured(2).trimmed();
        if (signatureVersionLabel) signatureVersionLabel->setText(tr("Signature Version: %1 (Last Updated: %2)").arg(signatureVer, signatureDate));
    } else {
        if (signatureVersionLabel) signatureVersionLabel->setText(tr("Signature Version: Not Found"));
        qWarning() << "Could not parse Signature version from clamscan output:" << clamavOutput;
    }
}

void MainWindow::scheduledRecursiveScanCheckBox_toggled(bool checked)
{
    m_scheduledRecursiveScanEnabled = checked;
}

void MainWindow::scheduledHeuristicAlertsCheckBox_toggled(bool checked)
{
    m_scheduledHeuristicAlertsEnabled = checked;
}

void MainWindow::scheduledEncryptedDocumentsAlertsCheckBox_toggled(bool checked)
{
    m_scheduledEncryptedDocumentsAlertsEnabled = checked;
}

// ****************************************************************************
// New Scheduled Scan Option Slots
// ****************************************************************************
void MainWindow::scheduledScanArchivesCheckBox_toggled(bool checked)
{
    m_scheduledScanArchivesEnabled = checked;
}

void MainWindow::scheduledBellOnVirusCheckBox_toggled(bool checked)
{
    m_scheduledBellOnVirusEnabled = checked;
}

void MainWindow::scheduledMoveInfectedCheckBox_toggled(bool checked)
{
    m_scheduledMoveInfectedEnabled = checked;
    ui->scheduledQuarantinePathLineEdit->setEnabled(checked);
    ui->browseScheduledQuarantineButton->setEnabled(checked);
}

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
    QString scansDirPath = QStandardPaths::writableLocation(QStandardPaths::HomeLocation) + "/.calamity/scans";
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
    ui->pathLineEdit->setText(path);
    ui->outputLog->clear();
    ui->outputLog->append(QString("Scanning: %1").arg(path));
    QApplication::processEvents(); // Force UI update
    scanButton_clicked();
}



