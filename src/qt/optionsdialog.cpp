#include "optionsdialog.h"
#include "optionsmodel.h"
#include "bitcoinamountfield.h"
#include "monitoreddatamapper.h"
#include "guiutil.h"
#include "bitcoinunits.h"
#include "qvaluecombobox.h"

#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QPushButton>
#include <QListWidget>
#include <QStackedWidget>

#include <QCheckBox>
#include <QLabel>
#include <QLineEdit>
#include <QIntValidator>
#include <QDoubleValidator>
#include <QRegExpValidator>
#include <QDialogButtonBox>

/* First page of options */
class MainOptionsPage : public QWidget
{
    Q_OBJECT
public:
    explicit MainOptionsPage(QWidget *parent=0);

    void setMapper(MonitoredDataMapper *mapper);
private:
    QCheckBox *bitcoin_at_startup;
#ifndef Q_WS_MAC
    QCheckBox *minimize_to_tray;
#endif
    QCheckBox *map_port_upnp;
#ifndef Q_WS_MAC
    QCheckBox *minimize_on_close;
#endif
    QCheckBox *connect_socks4;
    QCheckBox *detach_database;
    QLineEdit *proxy_ip;
    QLineEdit *proxy_port;
    BitcoinAmountField *fee_edit;

signals:

public slots:

};

class DisplayOptionsPage : public QWidget
{
    Q_OBJECT
public:
    explicit DisplayOptionsPage(QWidget *parent=0);

    void setMapper(MonitoredDataMapper *mapper);
private:
    QValueComboBox *unit;
    QCheckBox *display_addresses;
signals:

public slots:

};

#include "optionsdialog.moc"

OptionsDialog::OptionsDialog(QWidget *parent):
    QDialog(parent), contents_widget(0), pages_widget(0),
    model(0), main_page(0), display_page(0)
{
    contents_widget = new QListWidget();
    contents_widget->setMaximumWidth(128);

    pages_widget = new QStackedWidget();
    pages_widget->setMinimumWidth(300);

    QListWidgetItem *item_main = new QListWidgetItem(tr("Main"));
    contents_widget->addItem(item_main);
    main_page = new MainOptionsPage(this);
    pages_widget->addWidget(main_page);

    QListWidgetItem *item_display = new QListWidgetItem(tr("Display"));
    contents_widget->addItem(item_display);
    display_page = new DisplayOptionsPage(this);
    pages_widget->addWidget(display_page);

    contents_widget->setCurrentRow(0);

    QHBoxLayout *main_layout = new QHBoxLayout();
    main_layout->addWidget(contents_widget);
    main_layout->addWidget(pages_widget, 1);

    QVBoxLayout *layout = new QVBoxLayout();
    layout->addLayout(main_layout);

    QDialogButtonBox *buttonbox = new QDialogButtonBox();
    buttonbox->setStandardButtons(QDialogButtonBox::Apply|QDialogButtonBox::Ok|QDialogButtonBox::Cancel);
    apply_button = buttonbox->button(QDialogButtonBox::Apply);
    layout->addWidget(buttonbox);

    setLayout(layout);
    setWindowTitle(tr("Options"));

    /* Widget-to-option mapper */
    mapper = new MonitoredDataMapper(this);
    mapper->setSubmitPolicy(QDataWidgetMapper::ManualSubmit);
    mapper->setOrientation(Qt::Vertical);
    /* enable apply button when data modified */
    connect(mapper, SIGNAL(viewModified()), this, SLOT(enableApply()));
    /* disable apply button when new data loaded */
    connect(mapper, SIGNAL(currentIndexChanged(int)), this, SLOT(disableApply()));

    /* Event bindings */
    connect(contents_widget, SIGNAL(currentRowChanged(int)), this, SLOT(changePage(int)));
    connect(buttonbox->button(QDialogButtonBox::Ok), SIGNAL(clicked()), this, SLOT(okClicked()));
    connect(buttonbox->button(QDialogButtonBox::Cancel), SIGNAL(clicked()), this, SLOT(cancelClicked()));
    connect(buttonbox->button(QDialogButtonBox::Apply), SIGNAL(clicked()), this, SLOT(applyClicked()));
}

void OptionsDialog::setModel(OptionsModel *model)
{
    this->model = model;

    mapper->setModel(model);
    main_page->setMapper(mapper);
    display_page->setMapper(mapper);

    mapper->toFirst();
}

void OptionsDialog::changePage(int index)
{
    pages_widget->setCurrentIndex(index);
}

void OptionsDialog::okClicked()
{
    mapper->submit();
    accept();
}

void OptionsDialog::cancelClicked()
{
    reject();
}

void OptionsDialog::applyClicked()
{
    mapper->submit();
    apply_button->setEnabled(false);
}

void OptionsDialog::enableApply()
{
    apply_button->setEnabled(true);
}

void OptionsDialog::disableApply()
{
    apply_button->setEnabled(false);
}

MainOptionsPage::MainOptionsPage(QWidget *parent):
        QWidget(parent)
{
    QVBoxLayout *layout = new QVBoxLayout();

    bitcoin_at_startup = new QCheckBox(tr("&Start Peershares on system startup"));
    bitcoin_at_startup->setToolTip(tr("Automatically start Peershares after the computer is turned on"));
    layout->addWidget(bitcoin_at_startup);

#ifndef Q_WS_MAC
    minimize_to_tray = new QCheckBox(tr("&Minimize to the tray instead of the taskbar"));
    minimize_to_tray->setToolTip(tr("Show only a tray icon after minimizing the window"));
    layout->addWidget(minimize_to_tray);

    minimize_on_close = new QCheckBox(tr("M&inimize on close"));
    minimize_on_close->setToolTip(tr("Minimize instead of exit the application when the window is closed. When this option is enabled, the application will be closed only after selecting Quit in the menu."));
    layout->addWidget(minimize_on_close);
#endif

    map_port_upnp = new QCheckBox(tr("Map port using &UPnP"));
    map_port_upnp->setToolTip(tr("Automatically open the Peershares client port on the router. This only works when your router supports UPnP and it is enabled."));
    layout->addWidget(map_port_upnp);

    connect_socks4 = new QCheckBox(tr("&Connect through SOCKS4 proxy:"));
    connect_socks4->setToolTip(tr("Connect to the Peershares network through a SOCKS4 proxy (e.g. when connecting through Tor)"));
    layout->addWidget(connect_socks4);

    QHBoxLayout *proxy_hbox = new QHBoxLayout();
    proxy_hbox->addSpacing(18);
    QLabel *proxy_ip_label = new QLabel(tr("Proxy &IP: "));
    proxy_hbox->addWidget(proxy_ip_label);
    proxy_ip = new QLineEdit();
    proxy_ip->setMaximumWidth(140);
    proxy_ip->setEnabled(false);
    proxy_ip->setValidator(new QRegExpValidator(QRegExp("[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}"), this));
    proxy_ip->setToolTip(tr("IP address of the proxy (e.g. 127.0.0.1)"));
    proxy_ip_label->setBuddy(proxy_ip);
    proxy_hbox->addWidget(proxy_ip);
    QLabel *proxy_port_label = new QLabel(tr("&Port: "));
    proxy_hbox->addWidget(proxy_port_label);
    proxy_port = new QLineEdit();
    proxy_port->setMaximumWidth(55);
    proxy_port->setValidator(new QIntValidator(0, 65535, this));
    proxy_port->setEnabled(false);
    proxy_port->setToolTip(tr("Port of the proxy (e.g. 1234)"));
    proxy_port_label->setBuddy(proxy_port);
    proxy_hbox->addWidget(proxy_port);
    proxy_hbox->addStretch(1);

    layout->addLayout(proxy_hbox);
    QLabel *fee_help = new QLabel(tr("Mandatory network transaction fee per kB transferred. Most transactions are 1 kB and incur a 0.01 share fee. Note: transfer size may increase depending on the number of input transactions totaled to fund the output."));
    fee_help->setWordWrap(true);
    layout->addWidget(fee_help);

    QHBoxLayout *fee_hbox = new QHBoxLayout();
    fee_hbox->addSpacing(18);
    QLabel *fee_label = new QLabel(tr("Additional network &fee"));
    fee_hbox->addWidget(fee_label);
    fee_edit = new BitcoinAmountField();
    fee_edit->setDisabled(true);

    fee_label->setBuddy(fee_edit);
    fee_hbox->addWidget(fee_edit);
    fee_hbox->addStretch(1);

    layout->addLayout(fee_hbox);

    detach_database = new QCheckBox(tr("Detach databases at shutdown"));
    detach_database->setToolTip(tr("Detach block and address databases at shutdown. This means they can be moved to another data directory, but it slows down shutdown. The wallet is always detached."));
    layout->addWidget(detach_database);

    layout->addStretch(1); // Extra space at bottom

    setLayout(layout);

    connect(connect_socks4, SIGNAL(toggled(bool)), proxy_ip, SLOT(setEnabled(bool)));
    connect(connect_socks4, SIGNAL(toggled(bool)), proxy_port, SLOT(setEnabled(bool)));

#ifndef USE_UPNP
    map_port_upnp->setDisabled(true);
#endif
}

void MainOptionsPage::setMapper(MonitoredDataMapper *mapper)
{
    // Map model to widgets
    mapper->addMapping(bitcoin_at_startup, OptionsModel::StartAtStartup);
#ifndef Q_WS_MAC
    mapper->addMapping(minimize_to_tray, OptionsModel::MinimizeToTray);
#endif
    mapper->addMapping(map_port_upnp, OptionsModel::MapPortUPnP);
#ifndef Q_WS_MAC
    mapper->addMapping(minimize_on_close, OptionsModel::MinimizeOnClose);
#endif
    mapper->addMapping(connect_socks4, OptionsModel::ConnectSOCKS4);
    mapper->addMapping(proxy_ip, OptionsModel::ProxyIP);
    mapper->addMapping(proxy_port, OptionsModel::ProxyPort);
    mapper->addMapping(fee_edit, OptionsModel::Fee);
    mapper->addMapping(detach_database, OptionsModel::DetachDatabases);
}

DisplayOptionsPage::DisplayOptionsPage(QWidget *parent):
        QWidget(parent)
{
    QVBoxLayout *layout = new QVBoxLayout();

    QHBoxLayout *unit_hbox = new QHBoxLayout();
    unit_hbox->addSpacing(18);
    QLabel *unit_label = new QLabel(tr("&Unit to show amounts in: "));
    unit_hbox->addWidget(unit_label);
    unit = new QValueComboBox(this);
    unit->setModel(new BitcoinUnits(this));
    unit->setToolTip(tr("Choose the default subdivision unit to show in the interface, and when sending coins"));

    unit_label->setBuddy(unit);
    unit_hbox->addWidget(unit);

    layout->addLayout(unit_hbox);

    display_addresses = new QCheckBox(tr("&Display addresses in transaction list"), this);
    display_addresses->setToolTip(tr("Whether to show Peershares addresses in the transaction list"));
    layout->addWidget(display_addresses);

    layout->addStretch();

    setLayout(layout);
}

void DisplayOptionsPage::setMapper(MonitoredDataMapper *mapper)
{
    mapper->addMapping(unit, OptionsModel::DisplayUnit);
    mapper->addMapping(display_addresses, OptionsModel::DisplayAddresses);
}
