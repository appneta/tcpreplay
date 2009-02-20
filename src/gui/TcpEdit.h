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
  int addPlugin(int plugin_id);

  /// Add a plugin by its name.
  int addPlugin(QString const & plugin_name);

  int setSkipBroadcast(bool);
  //int setFixlen(tcpedit_fixlen);
  int setFixCsum(bool);
  int setEfcs(bool);
  //int setTtlMode(tcpedit_ttl_mode);
  int setTtlValue(unsigned char);
  int setTos(unsigned char);
  int setSeed(int);
  int setMtu(int);
  int setMaxpacket(int);
  int setCidrmap_s2c(QString const &);
  int setCidrmap_c2s(QString const &);
  int setSrcIpMap(QString const &);
  int setDstIpMap(QString const &);
  int setPortMap(QString const &);

private:
  struct Private;
  Private * d;
};

#endif // _TCP_EDIT_H_
