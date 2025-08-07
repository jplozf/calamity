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
{
    ui->setupUi(this);
    setWindowTitle("Calamity"); // Set the window title
    setStyleSheet(
        "QMainWindow, QWidget, QFrame { background-color: #FADA5E; }"); // Set background color to Naples' yellow for main window and panels

    // Initialize QProcess
    clamscanProcess = new QProcess(this);
    versionCheckProcess = new QProcess(this);

    // Connect QProcess signals to slots
    connect(clamscanProcess, &QProcess::readyReadStandardOutput, this, &MainWindow::readClamscanOutput);
    connect(clamscanProcess, &QProcess::readyReadStandardError, this, &MainWindow::readClamscanOutput);
    connect(clamscanProcess, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished), this, &MainWindow::clamscanFinished);
    connect(clamscanProcess, &QProcess::errorOccurred, this, &MainWindow::clamscanErrorOccurred);

    // Connect UI signals to slots (assuming widget names from Qt Designer)
    // User needs to ensure these widget names match their .ui file
    connect(ui->stopButton, &QPushButton::clicked, this, &MainWindow::on_stopButton_clicked);
    connect(ui->clearOutputButton, &QPushButton::clicked, this, &MainWindow::on_clearOutputButton_clicked);
    connect(ui->moveInfectedCheckBox, &QCheckBox::toggled, this, &MainWindow::on_moveInfectedCheckBox_toggled);

    // Connect scheduling UI signals to slots
    connect(ui->saveScanScheduleButton, &QPushButton::clicked, this, &MainWindow::on_saveScanScheduleButton_clicked);
    connect(ui->saveUpdateScheduleButton, &QPushButton::clicked, this, &MainWindow::on_saveUpdateScheduleButton_clicked);
    connect(ui->updateNowButton,
            &QPushButton::clicked,
            this,
            &MainWindow::on_updateNowButton_clicked);
    connect(ui->refreshVersionsButton, &QPushButton::clicked, this, &MainWindow::on_refreshVersionsButton_clicked);

    // Connect exclusion UI signals to slots
    connect(ui->addExclusionButton, &QPushButton::clicked, this, &MainWindow::handleAddExclusionButtonClicked);
    connect(ui->removeExclusionButton, &QPushButton::clicked, this, &MainWindow::handleRemoveExclusionButtonClicked);

    // Connect history UI signals to slots
    connect(ui->clearHistoryButton, &QPushButton::clicked, this, &MainWindow::on_clearHistoryButton_clicked);

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

    connect(scanSchedulerTimer, &QTimer::timeout, this, &MainWindow::on_scanSchedulerTimer_timeout);
    connect(updateSchedulerTimer, &QTimer::timeout, this, &MainWindow::on_updateSchedulerTimer_timeout);

    loadScheduleSettings();
    setupSchedulers();
    loadUiSettings(); // Load UI settings on startup
    on_moveInfectedCheckBox_toggled(ui->moveInfectedCheckBox->isChecked()); // Update quarantine path line edit state based on loaded setting
    loadExclusionSettings(); // Load exclusion settings on startup
    loadScanHistory(); // Load scan history on startup

    // Initialize QLabel pointers (assuming they exist in .ui file)
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
    connect(scanAction, &QAction::triggered, this, &MainWindow::on_actionScan_triggered);
    trayMenu->addAction(scanAction);

    QAction *showHideAction = new QAction(tr("Show / Hide"), this);
    connect(showHideAction, &QAction::triggered, this, &MainWindow::on_actionShowHide_triggered);
    trayMenu->addAction(showHideAction);

    trayMenu->addSeparator();

    QAction *quitAction = new QAction(tr("Quit"), this);
    connect(quitAction, &QAction::triggered, this, &MainWindow::on_actionQuit_triggered);
    trayMenu->addAction(quitAction);

    trayIcon->setContextMenu(trayMenu);
    trayIcon->setIcon(QIcon(":/icons/app_icon.png")); // You need to add an icon resource
    trayIcon->setToolTip("Calamity");

    connect(trayIcon, &QSystemTrayIcon::activated, this, &MainWindow::on_trayIcon_activated);

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
        /*
        trayIcon->showMessage("Calamity",
                              tr("Application minimized to tray."),
                              QSystemTrayIcon::Information,
                              2000);
        */
        event->ignore();
    } else {
        event->accept();
    }
}

// ****************************************************************************
// on_trayIcon_activated()
// ****************************************************************************
void MainWindow::on_trayIcon_activated(QSystemTrayIcon::ActivationReason reason)
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
// on_actionShowHide_triggered()
// ****************************************************************************
void MainWindow::on_actionShowHide_triggered()
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
// on_actionQuit_triggered()
// ****************************************************************************
void MainWindow::on_actionQuit_triggered()
{
    QApplication::quit();
}

// ****************************************************************************
// on_actionScan_triggered()
// ****************************************************************************
void MainWindow::on_actionScan_triggered()
{
    on_scanButton_clicked(); // Reuse the existing scan logic
}

// ****************************************************************************
// on_browseButton_clicked()
// ****************************************************************************
void MainWindow::on_browseButton_clicked()
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
// on_scanButton_clicked()
// ****************************************************************************
void MainWindow::on_scanButton_clicked()
{
    QString pathToScan = ui->pathLineEdit->text();
    if (pathToScan.isEmpty()) {
        QMessageBox::warning(this, tr("Input Error"), tr("Please select a file or directory to scan."));
        return;
    }

    if (clamscanProcess->state() == QProcess::Running) {
        QMessageBox::information(this, tr("Scan in Progress"), tr("A scan is already running. Please wait or stop the current scan."));
        return;
    }

    ui->outputLog->clear();
    updateStatusBar("Starting scan...");
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
// on_stopButton_clicked()
// ****************************************************************************
void MainWindow::on_stopButton_clicked()
{
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
// on_clearOutputButton_clicked()
// ****************************************************************************
void MainWindow::on_clearOutputButton_clicked()
{
    ui->outputLog->clear();
    updateStatusBar("Output cleared.");
}

// ****************************************************************************
// on_moveInfectedCheckBox_toggled()
// ****************************************************************************
void MainWindow::on_moveInfectedCheckBox_toggled(bool checked)
{
    ui->quarantinePathLineEdit->setEnabled(checked);
}

// ****************************************************************************
// readClamscanOutput()
// ****************************************************************************
void MainWindow::readClamscanOutput()
{
    QString txt;
    txt = clamscanProcess->readAllStandardOutput().trimmed();
    if (txt != "" && txt != "\n" && txt != "\r") {
        ui->outputLog->append(txt);
    }
    txt = clamscanProcess->readAllStandardError().trimmed();
    if (txt != "" && txt != "\n" && txt != "\r") {
        ui->outputLog->append(txt);
    }
}

// ****************************************************************************
// clamscanFinished()
// ****************************************************************************
void MainWindow::clamscanFinished(int exitCode, QProcess::ExitStatus exitStatus)
{
    Q_UNUSED(exitStatus); // Not using exitStatus directly, but keeping for signature

    QString statusMessage;
    QString scanStatus;
    int threats = 0;

    if (exitCode == 0) {
        statusMessage = "Scan finished: No threats found.";
        scanStatus = "Clean";
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
    } else if (exitCode == 2) {
        statusMessage = "Scan finished: Error occurred.";
        scanStatus = "Error";
    } else {
        statusMessage = QString("Scan finished with exit code: %1").arg(exitCode);
        scanStatus = "Unknown Error";
    }
    trayIcon->showMessage("Calamity", tr("Scan finished."), QSystemTrayIcon::Information, 2000);
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
    arguments << "--stdout" << "--no-summary"; // Ensure output goes to stdout and no summary

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

    // Add exclusion paths
    for (const QString &path : qAsConst(exclusionPaths)) {
        arguments << "--exclude=" + path;
    }

    // Add other desired clamscan options here based on your UI
    // Example: arguments << "--recursive"; // Always scan directories recursively

    return arguments;
}

// ****************************************************************************
// on_browseQuarantineButton_clicked()
// ****************************************************************************
void MainWindow::on_browseQuarantineButton_clicked()
{
    QString path = QFileDialog::getExistingDirectory(this, tr("Select Quarantine Directory"),
                                                 QDir::homePath(),
                                                 QFileDialog::ShowDirsOnly | QFileDialog::DontResolveSymlinks);
    if (!path.isEmpty()) {
        ui->quarantinePathLineEdit->setText(path);
    }
}

// ****************************************************************************
// on_browseScheduledScanPathButton_clicked()
// ****************************************************************************
void MainWindow::on_browseScheduledScanPathButton_clicked()
{
    QString path = QFileDialog::getExistingDirectory(this, tr("Select Directory to Scan"),
                                                 QDir::homePath(),
                                                 QFileDialog::ShowDirsOnly | QFileDialog::DontResolveSymlinks);
    if (!path.isEmpty()) {
        ui->scheduledScanPathLineEdit->setText(path);
    }
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
    updateStatusBar("Starting scheduled scan...");

    QStringList arguments;
    arguments << "--stdout" << "--no-summary";
    // Add other desired clamscan options for scheduled scans here
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
    updateStatusBar("Starting scheduled update (freshclam)...");

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
// on_saveScanScheduleButton_clicked()
// ****************************************************************************
void MainWindow::on_saveScanScheduleButton_clicked()
{
    saveScheduleSettings();
    startScanScheduler();
}

// ****************************************************************************
// on_saveUpdateScheduleButton_clicked()
// ****************************************************************************
void MainWindow::on_saveUpdateScheduleButton_clicked()
{
    saveScheduleSettings();
    startUpdateScheduler();
}

// ****************************************************************************
// on_scanSchedulerTimer_timeout()
// ****************************************************************************
void MainWindow::on_scanSchedulerTimer_timeout()
{
    runScheduledScan();
}

// ****************************************************************************
// on_updateSchedulerTimer_timeout()
// ****************************************************************************
void MainWindow::on_updateSchedulerTimer_timeout()
{
    runScheduledUpdate();
}

// ****************************************************************************
// on_refreshVersionsButton_clicked()
// ****************************************************************************
void MainWindow::on_refreshVersionsButton_clicked()
{
    updateVersionInfo();
}

// ****************************************************************************
// on_updateNowButton_clicked()
// ****************************************************************************
void MainWindow::on_updateNowButton_clicked()
{
    if (clamscanProcess->state() == QProcess::Running) {
        qWarning() << "A scan is running. Skipping update.";
        updateStatusBar("Update skipped: Scan in progress.");
        return;
    }

    ui->outputLog->clear();
    updateStatusBar("Starting update (freshclam)...");

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
// on_browseExclusionButton_clicked()
// ****************************************************************************
void MainWindow::on_browseExclusionButton_clicked()
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
    settings->endGroup();
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
    qDebug() << "Displaying scan history. Number of entries:" << scanHistory.size();
    for (const ScanResult &result : qAsConst(scanHistory)) {
        int row = ui->scanHistoryTable->rowCount();
        ui->scanHistoryTable->insertRow(row);
        ui->scanHistoryTable->setItem(row, 0, new QTableWidgetItem(result.timestamp.toString("yyyy-MM-dd hh:mm:ss")));
        ui->scanHistoryTable->setItem(row, 1, new QTableWidgetItem(result.scannedPath));
        ui->scanHistoryTable->setItem(row, 2, new QTableWidgetItem(result.status));
        ui->scanHistoryTable->setItem(row, 3, new QTableWidgetItem(QString::number(result.threatsFound)));

        qDebug() << "Added row:" << result.timestamp.toString("yyyy-MM-dd hh:mm:ss")
                 << result.scannedPath << result.status << result.threatsFound;
    }
    ui->scanHistoryTable->resizeColumnsToContents();
    ui->scanHistoryTable->viewport()->update(); // Force repaint of the viewport
}

// ****************************************************************************
// on_clearHistoryButton_clicked()
// ****************************************************************************
void MainWindow::on_clearHistoryButton_clicked()
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


