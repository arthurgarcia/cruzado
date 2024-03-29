// Copyright (c) 2017-2018 The cruZado developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_CRUZADOADDRESSVALIDATOR_H
#define BITCOIN_QT_CRUZADOADDRESSVALIDATOR_H

#include <QValidator>

/** Base58 entry widget validator, checks for valid characters and
 * removes some whitespace.
 */
class cruZadoAddressEntryValidator : public QValidator
{
    Q_OBJECT

public:
    explicit cruZadoAddressEntryValidator(QObject *parent);

    State validate(QString &input, int &pos) const;
};

/** cruZado address widget validator, checks for a valid cruzado address.
 */
class cruZadoAddressCheckValidator : public QValidator
{
    Q_OBJECT

public:
    explicit cruZadoAddressCheckValidator(QObject *parent);

    State validate(QString &input, int &pos) const;
};

#endif // BITCOIN_QT_CRUZADOADDRESSVALIDATOR_H
