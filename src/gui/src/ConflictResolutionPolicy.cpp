#include "ConflictResolutionPolicy.h"

#include <utility>

QByteArray ConflictResolutionPolicy::scopeKey(const QUuid& peerUuid, const QByteArray& batchId)
{
    if (peerUuid.isNull() || batchId.size() != 16) return {};
    return peerUuid.toRfc4122() + batchId;
}

ConflictAction ConflictResolutionPolicy::resolve(const ConflictRequest& request, const Callback& callback)
{
    const QByteArray key=scopeKey(request.peerUuid,request.batchId);
    auto cached=key.isEmpty()?batchDecisions_.end():batchDecisions_.find(key);
    const bool finalItem=request.itemCount>0 && request.itemIndex+1>=request.itemCount;
    const bool validIdentity=request.transferId.size()==16 && request.itemCount>0 && request.itemIndex<request.itemCount;
    if(cached!=batchDecisions_.end()){
        const bool validSequence=validIdentity && cached->itemCount==request.itemCount &&
            request.itemIndex>cached->lastItemIndex && !cached->seenTransferIds.contains(request.transferId);
        if(validSequence){
            cached->seenTransferIds.insert(request.transferId);
            cached->lastItemIndex=request.itemIndex;
            const ConflictAction action=cached->action;
            if(finalItem)batchDecisions_.erase(cached);
            return action;
        }
        batchDecisions_.erase(cached);
        const ConflictDecision fresh=callback?callback(request):ConflictDecision{};
        if(fresh.applyToAll&&!key.isEmpty()&&!finalItem&&validIdentity){
            BatchState state;state.action=fresh.action;state.itemCount=request.itemCount;
            state.lastItemIndex=request.itemIndex;state.seenTransferIds.insert(request.transferId);
            batchDecisions_.insert(key,std::move(state));
        }
        return fresh.action;
    }

    const ConflictDecision decision=callback?callback(request):ConflictDecision{};
    if(decision.applyToAll && !key.isEmpty() && !finalItem && validIdentity){
        if(batchDecisions_.size()>=64)batchDecisions_.clear();
        BatchState state;state.action=decision.action;state.itemCount=request.itemCount;
        state.lastItemIndex=request.itemIndex;state.seenTransferIds.insert(request.transferId);
        batchDecisions_.insert(key,std::move(state));
    }
    return decision.action;
}

void ConflictResolutionPolicy::recordNonConflict(const ConflictRequest& request)
{
    const QByteArray key=scopeKey(request.peerUuid,request.batchId);
    auto cached=key.isEmpty()?batchDecisions_.end():batchDecisions_.find(key);
    if(cached==batchDecisions_.end())return;
    const bool valid=request.transferId.size()==16&&request.itemCount>0&&request.itemIndex<request.itemCount&&
        cached->itemCount==request.itemCount&&request.itemIndex>cached->lastItemIndex&&
        !cached->seenTransferIds.contains(request.transferId);
    if(!valid){batchDecisions_.erase(cached);return;}
    cached->lastItemIndex=request.itemIndex;
    cached->seenTransferIds.insert(request.transferId);
}

void ConflictResolutionPolicy::completeBatch(const QUuid& peerUuid,const QByteArray& batchId,quint32 itemCount)
{
    const QByteArray key=scopeKey(peerUuid,batchId);
    const auto it=batchDecisions_.find(key);
    if(it!=batchDecisions_.end() && it->itemCount==itemCount)batchDecisions_.erase(it);
}

void ConflictResolutionPolicy::resetPeer(const QUuid& peerUuid)
{
    if(peerUuid.isNull())return;
    const QByteArray prefix=peerUuid.toRfc4122();
    for(auto it=batchDecisions_.begin();it!=batchDecisions_.end();)
        if(it.key().startsWith(prefix))it=batchDecisions_.erase(it);else ++it;
}

void ConflictResolutionPolicy::resetAll(){batchDecisions_.clear();}
