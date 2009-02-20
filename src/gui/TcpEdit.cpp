/**
 * \author Abdelrazak Younes
 *
 * Copyright (c) 2009 Aaron Turner.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the names of the copyright owners nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "TcpEdit.h"

#include "plugins.h"
#include "tcpedit_api.h"
#include "tcpedit.h"

#include <QString>

struct TcpEdit::Private
{
    Private(): tcpedit(0), dlt(0)
    {
        // FIXME: initialise dlt!
        //dlt = ???

        if (tcpedit_init(&tcpedit, dlt) < 0) {
            QString msg = "Error initializing tcpedit: ";
            msg += tcpedit_geterr(tcpedit);
            throw msg;
        }
    }
    tcpedit_t * tcpedit;
    int dlt;
};


TcpEdit::TcpEdit(): d(new TcpEdit::Private)
{
}


TcpEdit::~TcpEdit()
{
    delete d;
}


static void handleError(tcpedit_t * tcpedit, int res)
{
    static QString msg;
    switch (res) {
    case TCPEDIT_OK: return;
    case TCPEDIT_ERROR:
    case TCPEDIT_WARN:
    case TCPEDIT_SOFT_ERROR:
        msg = tcpedit_geterr(tcpedit);
    }
    // FIXME: create a proper standard exception...
    throw msg;
}


void TcpEdit::addPlugin(int plugin_id)
{
    int const res = tcpedit_set_encoder_dltplugin_byid(d->tcpedit, plugin_id);
    handleError(d->tcpedit, res);
}


void TcpEdit::addPlugin(QString const & plugin_name)
{
    int const res = tcpedit_set_encoder_dltplugin_byname(d->tcpedit, plugin_name.toLocal8Bit().data());
    handleError(d->tcpedit, res);
}


void TcpEdit::setSkipBroadcast(bool value)
{
    int const res = tcpedit_set_skip_broadcast(d->tcpedit, value);
    handleError(d->tcpedit, res);
}


bool TcpEdit::skipBroadcast() const
{
    return d->tcpedit->skip_broadcast;
}


void TcpEdit::setFixLength(int value)
{
    int const res = tcpedit_set_fixlen(d->tcpedit, (tcpedit_fixlen) value);
    handleError(d->tcpedit, res);
}


int TcpEdit::fixLength() const
{
    return d->tcpedit->fixlen;
}


void TcpEdit::setFixCsum(bool value)
{
    int const res = tcpedit_set_fixcsum(d->tcpedit, value);
    handleError(d->tcpedit, res);
}


bool TcpEdit::fixCsum() const
{
    return d->tcpedit->fixcsum;
}


void TcpEdit::setEfcs(bool value)
{
    int const res = tcpedit_set_efcs(d->tcpedit, value);
    handleError(d->tcpedit, res);
}



bool TcpEdit::efcs() const
{
    return d->tcpedit->efcs;
}


void TcpEdit::setTtlMode(int value)
{
    int const res = tcpedit_set_ttl_mode(d->tcpedit, (tcpedit_ttl_mode) value);
    handleError(d->tcpedit, res);
}


int TcpEdit::ttlMode() const
{
    return d->tcpedit->ttl_mode;
}


void TcpEdit::setTtlValue(unsigned char value)
{
    int const res = tcpedit_set_ttl_value(d->tcpedit, value);
    handleError(d->tcpedit, res);
}


unsigned char TcpEdit::ttlValue() const
{
    return d->tcpedit->ttl_value;
}


void TcpEdit::setTos(unsigned char value)
{
    int const res = tcpedit_set_tos(d->tcpedit, value);
    handleError(d->tcpedit, res);
}


unsigned char TcpEdit::tos() const
{
    return d->tcpedit->tos;
}


void TcpEdit::setSeed(int value)
{
    int const res = tcpedit_set_seed(d->tcpedit, value);
    handleError(d->tcpedit, res);
}


int TcpEdit::seed() const
{
    return d->tcpedit->seed;
}


void TcpEdit::setMtu(int value)
{
    int const res = tcpedit_set_mtu(d->tcpedit, value);
    handleError(d->tcpedit, res);
}


int TcpEdit::mtu() const
{
    return d->tcpedit->mtu;
}


void TcpEdit::setMaxpacket(int value)
{
    int const res = tcpedit_set_maxpacket(d->tcpedit, value);
    handleError(d->tcpedit, res);
}



int TcpEdit::maxpacket() const
{
    return d->tcpedit->maxpacket;
}



void TcpEdit::setCidrmap_s2c(QString const & value)
{
    int const res = tcpedit_set_cidrmap_s2c(d->tcpedit, value.toLocal8Bit().data());
    handleError(d->tcpedit, res);
}


QString const & TcpEdit::cidrmap_s2c()
{
    // FIXME
    //return d->tcpedit->cidrmap_s2c;
    return QString();
}


void TcpEdit::setCidrmap_c2s(QString const & value)
{
    int const res = tcpedit_set_cidrmap_c2s(d->tcpedit, value.toAscii().data());
    handleError(d->tcpedit, res);
}


QString const & TcpEdit::cidrmap_c2s() const
{
    // FIXME
    //return d->tcpedit->cidrmap_c2s;
    return QString();
}


void TcpEdit::setSrcIpMap(QString const & value)
{
    int const res = tcpedit_set_srcip_map(d->tcpedit, value.toAscii().data());
    handleError(d->tcpedit, res);
}


QString const & TcpEdit::srcIpMap() const
{
    // FIXME
    //return d->tcpedit->skip_broadcast;
    return QString();
}


void TcpEdit::setDstIpMap(QString const & value)
{
    int const res = tcpedit_set_dstip_map(d->tcpedit, value.toAscii().data());
    handleError(d->tcpedit, res);
}


QString const & TcpEdit::dstIpMap() const
{
    // FIXME
    //return d->tcpedit->skip_broadcast;
    return QString();
}


void TcpEdit::setPortMap(QString const & value)
{
    int const res = tcpedit_set_port_map(d->tcpedit, value.toAscii().data());
    handleError(d->tcpedit, res);
}


QString const & TcpEdit::portMap() const
{
    // FIXME
    //return d->tcpedit->skip_broadcast;
    return QString();
}

