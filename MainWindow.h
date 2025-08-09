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

    // New slots for scheduled scan options
    void scheduledRecursiveScanCheckBox_toggled(bool checked);
    void scheduledHeuristicAlertsCheckBox_toggled(bool checked);
    void scheduledEncryptedDocumentsAlertsCheckBox_toggled(bool checked);

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
    void clearHistoryButtonClicked();

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