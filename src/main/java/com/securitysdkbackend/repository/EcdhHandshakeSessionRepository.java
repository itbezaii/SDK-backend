package com.securitysdkbackend.repository;

import com.securitysdkbackend.model.EcdhHandshakeSession;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface EcdhHandshakeSessionRepository
        extends CrudRepository<EcdhHandshakeSession, String> {
}
