#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QCloseEvent> // For closeEvent override
#include <QDateTime>
#include <QLabel>
#include <QMainWindow>
#include <QMenu>
#include <QProcess>  // REQUIRED for QProcess member
#include <QSettings> // For saving/loading settings
#include <QSystemTrayIcon>
#include <QTimer> // For scheduling
#include <QTemporaryFile>
#include <QLineEdit>
#include <QElapsedTimer>
#include "libs/SmtpClient-for-Qt/src/SmtpMime"

QT_BEGIN_NAMESPACE
namespace Ui {

class MainWindow;
}
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void onEmailReportCheckBox_toggled(bool checked);
    void onSaveEmailSettingsButton_clicked();
    void onTestEmailButton_clicked();
    void sendEmailReport(const QString &reportPath);
    void handleSmtpConnected();
    void handleSmtpAuthenticated();
    void handleSmtpMailSent();
    void handleSmtpError(SmtpClient::SmtpError e);
    void handleSmtpDisconnected();
    void updateScanStatusLed(bool scanning);
    void browseButton_clicked();
    void scanButton_clicked();
    void stopButton_clicked();
    void clearOutputButton_clicked();
    void moveInfectedCheckBox_toggled(bool checked);
    void readClamscanOutput();
    void clamscanFinished(int exitCode, QProcess::ExitStatus exitStatus);
    void clamscanErrorOccurred(QProcess::ProcessError error);

    // System Tray related slots
    void trayIconActivated(QSystemTrayIcon::ActivationReason reason);
    void showHideActionTriggered();
    void quitActionTriggered();
    void scanActionTriggered(); // To trigger scan from tray menu

    // Scheduling related slots
    void saveScanScheduleButtonClicked();
    void saveUpdateScheduleButtonClicked();
    void scanSchedulerTimerTimeout();
    void updateSchedulerTimerTimeout();
    void updateNowButtonClicked(); // Manual update button slot
    void refreshVersionsButtonClicked(); // Refresh versions button slot

    // Exclusion related slots
    void browseExclusionButtonClicked();
    void handleAddExclusionButtonClicked();
    void handleRemoveExclusionButtonClicked();

    // New browse slots
    void browseQuarantineButtonClicked();
    void browseScheduledScanPathButtonClicked();

    // New slots for scan options
    void recursiveScanCheckBox_toggled(bool checked);
    void heuristicAlertsCheckBox_toggled(bool checked);
    void encryptedDocumentsAlertsCheckBox_toggled(bool checked);
    void detectPuaCheckBox_toggled(bool checked);

    // New slots for scheduled scan options
    void scheduledRecursiveScanCheckBox_toggled(bool checked);
    void scheduledHeuristicAlertsCheckBox_toggled(bool checked);
    void scheduledEncryptedDocumentsAlertsCheckBox_toggled(bool checked);
    void scheduledDetectPuaCheckBox_toggled(bool checked);
    void scheduledScanArchivesCheckBox_toggled(bool checked);
    
    void scheduledMoveInfectedCheckBox_toggled(bool checked);
    void scheduledRemoveInfectedCheckBox_toggled(bool checked);
    void browseScheduledQuarantineButtonClicked();
    void openLastReportButtonClicked();
    void openReportsFolderButtonClicked();
    void openScanReportFolderButtonClicked();
    void openLastUpdateReportButtonClicked();
    void openUpdateReportsFolderButtonClicked();
    void openStatusPageButtonClicked();
    void on_updateHistoryTable_cellDoubleClicked(int row, int column);
    void refreshUpdateHistoryButtonClicked();
    QString timeConversion(qint64 msecs);

protected:
    void closeEvent(QCloseEvent *event) override;

private slots:
    void handleFileDropped(const QString &path);
    void onVersionCheckTimerTimeout();

private:
    void loadEmailSettings();
    void saveEmailSettings();
    void checkForUpdates();
    void onVersionCheckFinished();
    void onOnlineVersionCheckFinished();
    Ui::MainWindow *ui;
    QProcess *clamscanProcess;
    QProcess *m_updateCheckProcess;
    QProcess *m_onlineVersionCheckProcess;
    QSystemTrayIcon *trayIcon;
    QMenu *trayMenu;
    QTimer *scanSchedulerTimer;
    QTimer *updateSchedulerTimer;
    QTimer *m_versionCheckTimer;
    QTimer *m_updateVersionTimer;
    QSettings *settings;
    QProcess *versionCheckProcess;
    bool m_recursiveScanEnabled;
    bool m_heuristicAlertsEnabled;
    bool m_encryptedDocumentsAlertsEnabled;
    bool m_detectPuaEnabled;
    QTemporaryFile *m_logFile;
    QString m_lastScanTargetsDisplay; // Tracks last scan targets for history/logging
    QString m_lastCommand;            // The executable used (e.g., clamscan or sudo)
    QStringList m_lastArguments;      // Full argument list used for the last run
    QElapsedTimer m_scanTimer;        // Measures elapsed scan time
    QElapsedTimer m_updateTimer;      // Measures elapsed update time
    QDateTime m_updateStartedAt;      // Stores the start time of the update
    QDateTime m_scanStartedAt;        // Start timestamp
    QString m_lastReportPath;      // Path to last generated report
    bool m_scheduledRecursiveScanEnabled;
    bool m_scheduledHeuristicAlertsEnabled;
    bool m_scheduledEncryptedDocumentsAlertsEnabled;
    bool m_scheduledDetectPuaEnabled;
    bool m_scheduledScanArchivesEnabled;
    bool m_scheduledBellOnVirusEnabled;
    bool m_scheduledMoveInfectedEnabled;
    bool m_scheduledRemoveInfectedEnabled;
    int m_versionCheckInterval;
    int m_fullVersionCheckInterval;

    // Version Info Labels (assuming these are in .ui file)
    QLabel *appVersionLabel;
    QLabel *clamavVersionLabel;
    QLabel *signatureVersionLabel;
    // Cached version info
    QString m_clamavVersion;
    QString m_signatureVersionInfo;

    QPixmap ledGreenPixmap;
    QPixmap ledGrayPixmap;
    QLabel *scanStatusLed;

    QStringList exclusionPaths; // New: To store exclusion paths

    SmtpClient *smtpClient; // New: SmtpClient instance

    void createTrayIcon();
    void updateStatusBar(const QString &message);
    QStringList buildClamscanArguments();
    void setupSchedulers();
    void loadScheduleSettings();
    void saveScheduleSettings();
    void startScanScheduler();
    void startUpdateScheduler();
    void runScheduledScan();
    void runScheduledUpdate();
    void saveUiSettings();
    void loadUiSettings();
    void updateVersionInfo();
    void generateUpdateReport(const QByteArray &logData);
    void populateUpdateHistoryTable();
    void generateStatusPage();
    QString m_lastUpdateReportPath;

    // Scan History related slots
    void clearHistoryButtonClicked();
    void on_scanHistoryTable_cellDoubleClicked(int row, int column);

    // Update History related slots
    void clearUpdatesHistoryButtonClicked();

    // Structure to hold scan results
    struct ScanResult {
        QDateTime timestamp;
        QString scannedPath;
        QString status;
        int threatsFound;
    };
    QList<ScanResult> scanHistory; // List to store scan results

    // Structure to hold update results
    struct UpdateResult {
        QDateTime timestamp;
        QString status;
    };
    QList<UpdateResult> updateHistory; // List to store update results

    void loadExclusionSettings();
    void saveExclusionSettings();
    void loadScanHistory(); // New: Load scan history
    void saveScanHistory(); // New: Save scan history
    void addScanResult(const QString &path, const QString &status, int threats); // New: Add scan result to history
    void addUpdateResult(const QString &status); // New: Add update result to history
    void displayScanHistory(); // New: Display history in table

    // Helpers for multi-path support
    QStringList parsePathsText(const QString &text) const;
    QString joinPathsForDisplay(const QStringList &paths) const;
    void appendPathToLineEdit(QLineEdit *lineEdit, const QString &path);
};
#endif // MAINWINDOW_H
