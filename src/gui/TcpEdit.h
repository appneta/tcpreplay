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


#ifndef _TCP_EDIT_H_
#define _TCP_EDIT_H_

class QString;

class TcpEdit
{
public:
    TcpEdit();
    ~TcpEdit();

    /// Add a plugin by its id.
    void addPlugin(int plugin_id);

    /// Add a plugin by its name.
    void addPlugin(QString const & plugin_name);

    void setSkipBroadcast(bool);
    bool skipBroadcast() const;

    void setFixLength(int);
    int fixLength() const;

    void setFixCsum(bool);
    bool fixCsum() const;

    void setEfcs(bool);
    bool efcs() const;

    void setTtlMode(int);
    int ttlMode() const;

    void setTtlValue(unsigned char);
    unsigned char ttlValue() const;

    void setTos(unsigned char);
    unsigned char tos() const;

    void setSeed(int);
    int seed() const;

    void setMtu(int);
    int mtu() const;

    void setMaxpacket(int);
    int maxpacket() const;;

    void setCidrmap_s2c(QString const &);
    QString const & cidrmap_s2c();

    void setCidrmap_c2s(QString const &);
    QString const & cidrmap_c2s() const;

    void setSrcIpMap(QString const &);
    QString const & srcIpMap() const;

    void setDstIpMap(QString const &);
    QString const & dstIpMap() const;

    void setPortMap(QString const &);
    QString const & portMap() const;

private:
    struct Private;
    Private * d;
};

#endif // _TCP_EDIT_H_
