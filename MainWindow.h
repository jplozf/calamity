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
    void on_browseButton_clicked();
    void on_scanButton_clicked();
    void on_stopButton_clicked();
    void on_clearOutputButton_clicked();
    void on_moveInfectedCheckBox_toggled(bool checked);
    void readClamscanOutput();
    void clamscanFinished(int exitCode, QProcess::ExitStatus exitStatus);
    void clamscanErrorOccurred(QProcess::ProcessError error);

    // System Tray related slots
    void on_trayIcon_activated(QSystemTrayIcon::ActivationReason reason);
    void on_actionShowHide_triggered();
    void on_actionQuit_triggered();
    void on_actionScan_triggered(); // To trigger scan from tray menu

    // Scheduling related slots
    void on_saveScanScheduleButton_clicked();
    void on_saveUpdateScheduleButton_clicked();
    void on_scanSchedulerTimer_timeout();
    void on_updateSchedulerTimer_timeout();
    void on_updateNowButton_clicked(); // Manual update button slot
    void on_refreshVersionsButton_clicked(); // Refresh versions button slot

    // Exclusion related slots
    void on_browseExclusionButton_clicked();
    void handleAddExclusionButtonClicked();
    void handleRemoveExclusionButtonClicked();

    // New browse slots
    void on_browseQuarantineButton_clicked();
    void on_browseScheduledScanPathButton_clicked();

    // New slots for scan options
    void on_recursiveScanCheckBox_toggled(bool checked);
    void on_heuristicAlertsCheckBox_toggled(bool checked);
    void on_encryptedDocumentsAlertsCheckBox_toggled(bool checked);

    // New slots for scheduled scan options
    void on_scheduledRecursiveScanCheckBox_toggled(bool checked);
    void on_scheduledHeuristicAlertsCheckBox_toggled(bool checked);
    void on_scheduledEncryptedDocumentsAlertsCheckBox_toggled(bool checked);

protected:
    void closeEvent(QCloseEvent *event) override;

private:
    Ui::MainWindow *ui;
    QProcess *clamscanProcess;
    QSystemTrayIcon *trayIcon;
    QMenu *trayMenu;
    QTimer *scanSchedulerTimer;
    QTimer *updateSchedulerTimer;
    QSettings *settings;
    QProcess *versionCheckProcess;
    bool m_recursiveScanEnabled;
    bool m_heuristicAlertsEnabled;
    bool m_encryptedDocumentsAlertsEnabled;
    QTemporaryFile *m_logFile;
    bool m_scheduledRecursiveScanEnabled;
    bool m_scheduledHeuristicAlertsEnabled;
    bool m_scheduledEncryptedDocumentsAlertsEnabled;

    // Version Info Labels (assuming these are in .ui file)
    QLabel *appVersionLabel;
    QLabel *clamavVersionLabel;
    QLabel *signatureVersionLabel;

    QStringList exclusionPaths; // New: To store exclusion paths

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

    // Scan History related slots
    void on_clearHistoryButton_clicked();

    // Structure to hold scan results
    struct ScanResult {
        QDateTime timestamp;
        QString scannedPath;
        QString status;
        int threatsFound;
    };
    QList<ScanResult> scanHistory; // List to store scan results

    void loadExclusionSettings();
    void saveExclusionSettings();
    void loadScanHistory(); // New: Load scan history
    void saveScanHistory(); // New: Save scan history
    void addScanResult(const QString &path, const QString &status, int threats); // New: Add scan result to history
    void displayScanHistory(); // New: Display history in table
};
#endif // MAINWINDOW_H
