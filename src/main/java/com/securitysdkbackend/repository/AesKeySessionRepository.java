package com.securitysdkbackend.repository;

import com.securitysdkbackend.model.AesKeySession;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface AesKeySessionRepository
        extends CrudRepository<AesKeySession, String> {
}
