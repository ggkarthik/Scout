package com.prototype.vulnwatch.service;

import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;

final class OffsetLimitPageable implements Pageable {

    private final long offset;
    private final int pageSize;

    OffsetLimitPageable(long offset, int pageSize) {
        this.offset = Math.max(0L, offset);
        this.pageSize = Math.max(1, pageSize);
    }

    @Override
    public int getPageNumber() {
        return (int) (offset / pageSize);
    }

    @Override
    public int getPageSize() {
        return pageSize;
    }

    @Override
    public long getOffset() {
        return offset;
    }

    @Override
    public Sort getSort() {
        return Sort.unsorted();
    }

    @Override
    public Pageable next() {
        return new OffsetLimitPageable(offset + pageSize, pageSize);
    }

    @Override
    public Pageable previousOrFirst() {
        if (!hasPrevious()) {
            return first();
        }
        return new OffsetLimitPageable(offset - pageSize, pageSize);
    }

    @Override
    public Pageable first() {
        return new OffsetLimitPageable(0L, pageSize);
    }

    @Override
    public Pageable withPage(int pageNumber) {
        if (pageNumber < 0) {
            throw new IllegalArgumentException("Page index must not be less than zero");
        }
        return new OffsetLimitPageable((long) pageNumber * pageSize, pageSize);
    }

    @Override
    public boolean hasPrevious() {
        return offset > 0L;
    }
}
