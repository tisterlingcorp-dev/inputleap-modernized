/*
 * InputLeap -- mouse and keyboard sharing utility
 * Copyright (C) 2012-2016 Symless Ltd.
 * Copyright (C) 2012 Nick Bolton
 *
 * This package is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * found in the file LICENSE that should have accompanied this file.
 *
 * This package is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

// this class is a duplicate of /src/lib/ipc/Ipc.cpp

#include "Ipc.h"

const char*                kIpcMsgHello        = "IHEL%1i";
const char*                kIpcMsgLogLine        = "ILOG%s";
const char*                kIpcMsgCommand        = "ICMD%s%1i";
const char*                kIpcMsgStartRequest   = "ISTR%s%s%1i";
const char*                kIpcMsgReloadRequest  = "IRLD%s%s";
const char*                kIpcMsgStopRequest    = "ISTP%s%s";
const char*                kIpcMsgShutdown        = "ISDN";
const char*                kIpcMsgConnectionState = "ISTS%1i%1i%1i%s%s";
const char*                kIpcMsgCommandApplied   = "IACK%s";
