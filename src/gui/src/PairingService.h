/* InputLeap two-endpoint pairing protocol.
 *
 * Implements SRP-6a with SHA-256 and RFC 5054's 2048-bit group.  The display
 * code is shown out-of-band and MUST NOT be sent over the pairing channel.
 * Only public SRP values/proofs cross that channel.  A pair key is exposed on
 * the client only after M2 and on the inviter only after the client's M3,
 * providing explicit mutual key confirmation.
 */
#pragma once
#include <QByteArray>
#include <QJsonObject>
#include <QUuid>
#include <functional>
#include <memory>
#include <optional>

class PairingService {
public:
 struct PublicInvite { QByteArray inviteId,salt; QUuid localUuid,expectedRemoteUuid; qint64 createdAtMs=0,expiresAtMs=0; quint64 generation=0; QJsonObject toJson() const; };
 struct CreatedInvite { PublicInvite publicInvite; QByteArray displayCode; };
 struct ClientHello { QByteArray sessionId,A,inviteId; };
 struct ServerChallenge { QByteArray sessionId,B,inviteId; };
 struct ClientProof { QByteArray sessionId,M1; };
 struct ServerProof { QByteArray sessionId,M2; };
 struct FinalAck { QByteArray sessionId,M3; };
 enum class Status { Ok,Accepted,Malformed,Expired,AlreadyUsed,AttemptLimitReached,Revoked,InvalidIdentity,IdentityMismatch,UnknownInvite,InvalidInvite,InvalidClock,CryptoError,InvalidPublicValue,InvalidProof,UnknownSession,ResourceLimit };
 using Clock=std::function<qint64()>; using RandomBytes=std::function<QByteArray(qsizetype)>;
 explicit PairingService(Clock clock={},RandomBytes randomBytes={}); ~PairingService();
 PairingService(const PairingService&)=delete; PairingService& operator=(const PairingService&)=delete;
 std::optional<CreatedInvite> createInvite(const QUuid&,const QUuid&,int validityMinutes=5);
 std::optional<ClientHello> beginPairing(const PublicInvite&,const QByteArray& enteredCode,const QUuid& remoteUuid,const QUuid& inviterUuid);
 std::optional<ServerChallenge> respondToClient(const PublicInvite&,const ClientHello&);
 std::optional<ClientProof> answerChallenge(const ServerChallenge&);
 std::optional<ServerProof> verifyClientProof(const ClientProof&);
 std::optional<FinalAck> verifyServerProof(const ServerProof&);
 Status finalize(const FinalAck&);
 void revoke(const QUuid& remoteUuid); quint64 rotate(const QUuid& remoteUuid);
 std::optional<QByteArray> pairKey(const QUuid& remoteUuid) const;
 Status lastStatus() const;
private: struct Impl; std::unique_ptr<Impl> d;
};
