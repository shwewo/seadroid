package com.seafile.seadroid2.ui.dialog_fragment.viewmodel;

import android.text.TextUtils;

import androidx.lifecycle.MutableLiveData;

import com.blankj.utilcode.util.CollectionUtils;
import com.blankj.utilcode.util.GsonUtils;
import com.blankj.utilcode.util.TimeUtils;
import com.seafile.seadroid2.SeafException;
import com.seafile.seadroid2.baseviewmodel.BaseViewModel;
import com.seafile.seadroid2.config.DateFormatType;
import com.seafile.seadroid2.framework.http.HttpManager;
import com.seafile.seadroid2.framework.model.dirents.DirentPermissionModel;
import com.seafile.seadroid2.framework.model.objs.DirentShareLinkModel;
import com.seafile.seadroid2.ui.dialog_fragment.DialogService;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import io.reactivex.Single;
import io.reactivex.functions.Consumer;
import kotlin.coroutines.Continuation;

public class GetShareLinkPasswordViewModel extends BaseViewModel {
    private final MutableLiveData<DirentShareLinkModel> linkLiveData = new MutableLiveData<>();

    public MutableLiveData<DirentShareLinkModel> getLinkLiveData() {
        return linkLiveData;
    }

    public void getDirentFirstShareLink(String repoId, String path) {
        getRefreshLiveData().setValue(true);

        Single<List<DirentShareLinkModel>> single = HttpManager.getCurrentHttp().execute(DialogService.class).listAllShareLink(repoId, path);
        addSingleDisposable(single, new Consumer<List<DirentShareLinkModel>>() {
            @Override
            public void accept(List<DirentShareLinkModel> models) {
                if (CollectionUtils.isEmpty(models)) {
                    createDirentShareLink(repoId, path, null, null);
                } else {
                    Optional<DirentShareLinkModel> optional = models.stream().filter(f -> !f.is_expired).findFirst();
                    if (optional.isPresent()) {
                        getLinkLiveData().setValue(optional.get());
                        getRefreshLiveData().setValue(false);
                    } else {
                        createDirentShareLink(repoId, path, null, null);
                    }
                }
            }
        }, new Consumer<Throwable>() {
            @Override
            public void accept(Throwable throwable) throws Exception {
                SeafException seafException = getSeafExceptionByThrowable(throwable);
                getSeafExceptionLiveData().setValue(seafException);
                getRefreshLiveData().setValue(false);
            }
        });
    }

    public void createDirentShareLink(String repoId, String path, String password, Long selectedExpirationDateLong) {
        createShareLink(repoId, path, password, null, null, selectedExpirationDateLong, null);
    }

    public void createShareLink(String repoId, String path, String password, String user_scope, String desc, Long selectedExpirationDateLong, DirentPermissionModel permissions) {
        getRefreshLiveData().setValue(true);

        Map<String, Object> requestDataMap = new HashMap<>();
        requestDataMap.put("repo_id", repoId);
        requestDataMap.put("path", path);

        if (!TextUtils.isEmpty(password)) {
            requestDataMap.put("password", password);
        }

        if (!TextUtils.isEmpty(user_scope)) {
            requestDataMap.put("user_scope", user_scope);
        }

        if (!TextUtils.isEmpty(desc)) {
            requestDataMap.put("description", desc);
        }

        if (selectedExpirationDateLong != null) {
            String expireDayStr = TimeUtils.millis2String(selectedExpirationDateLong, DateFormatType.DATE_XXX);
            requestDataMap.put("expiration_time", expireDayStr);
        }

        Single<DirentShareLinkModel> single;
        if (permissions != null) {
            String perStr = GsonUtils.toJson(permissions);
            requestDataMap.put("permissions", perStr);
        }

        single = HttpManager.getCurrentHttp().execute(DialogService.class).createMultiShareLink(requestDataMap);

        addSingleDisposable(single, new Consumer<DirentShareLinkModel>() {
            @Override
            public void accept(DirentShareLinkModel direntShareLinkModel) throws Exception {
                getLinkLiveData().setValue(direntShareLinkModel);
                getRefreshLiveData().setValue(false);
            }
        }, new Consumer<Throwable>() {
            @Override
            public void accept(Throwable throwable) throws Exception {
                SeafException seafException = getSeafExceptionByThrowable(throwable);
                getSeafExceptionLiveData().setValue(seafException);
                getRefreshLiveData().setValue(false);
            }
        });
    }
}