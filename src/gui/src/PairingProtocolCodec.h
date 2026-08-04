#pragma once
#include "PairingService.h"
#include "ScreenSetupModel.h"
#include <QByteArray>
#include <QString>

class PairingProtocolCodec {
public:
    static constexpr quint32 Version=1;
    static constexpr quint32 MaxPayload=64*1024;
    enum class Type { Invite,Hello,Challenge,ClientProof,ServerProof,FinalAck,Success,Confirmed,DeviceMetadata,Error };
    struct Message { Type type=Type::Error; PairingService::PublicInvite invite; QByteArray sessionId,inviteId,value,authenticationTag; QUuid senderUuid,receiverUuid; std::vector<ScreenLayout::Monitor> monitors; QString error; };
    static Message invite(const PairingService::PublicInvite&);
    static Message success(const QByteArray& sessionId);
    static Message confirmed(const QByteArray& sessionId);
    static std::optional<Message> deviceMetadata(const QByteArray& pairKey,const QByteArray& sessionId,const QByteArray& inviteId,const QUuid& sender,const QUuid& receiver,const std::vector<ScreenLayout::Monitor>& monitors);
    static bool authenticateDeviceMetadata(const Message&,const QByteArray& pairKey,const QByteArray& expectedSessionId,const QByteArray& expectedInviteId,const QUuid& expectedSender,const QUuid& expectedReceiver);
    static Message error(const QString& text);
    static QByteArray encode(const Message&);
    static bool decodeFrame(const QByteArray&,Message*,QString*);
    static bool decodePayload(const QByteArray&,Message*,QString*);
};
